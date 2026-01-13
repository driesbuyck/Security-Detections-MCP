import Database from 'better-sqlite3';
import { homedir } from 'os';
import { join } from 'path';
import { mkdirSync, existsSync } from 'fs';
import type { Detection, IndexStats } from './types.js';

const CACHE_DIR = join(homedir(), '.cache', 'security-detections-mcp');
const DB_PATH = join(CACHE_DIR, 'detections.sqlite');

let db: Database.Database | null = null;

export function getDbPath(): string {
  return DB_PATH;
}

export function initDb(): Database.Database {
  if (db) return db;
  
  // Ensure cache directory exists
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true });
  }
  
  db = new Database(DB_PATH);
  
  // Create main detections table
  db.exec(`
    CREATE TABLE IF NOT EXISTS detections (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      query TEXT,
      source_type TEXT NOT NULL,
      mitre_ids TEXT,
      logsource_category TEXT,
      logsource_product TEXT,
      logsource_service TEXT,
      severity TEXT,
      status TEXT,
      author TEXT,
      date_created TEXT,
      date_modified TEXT,
      refs TEXT,
      falsepositives TEXT,
      tags TEXT,
      file_path TEXT,
      raw_yaml TEXT
    )
  `);
  
  // Create FTS5 virtual table for full-text search
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS detections_fts USING fts5(
      id,
      name,
      description,
      query,
      mitre_ids,
      tags,
      content='detections',
      content_rowid='rowid'
    )
  `);
  
  // Create triggers to keep FTS in sync
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ai AFTER INSERT ON detections BEGIN
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ad AFTER DELETE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_au AFTER UPDATE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags);
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags);
    END
  `);
  
  // Create indexes for common queries
  db.exec(`CREATE INDEX IF NOT EXISTS idx_source_type ON detections(source_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_severity ON detections(severity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_product ON detections(logsource_product)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_category ON detections(logsource_category)`);
  
  return db;
}

export function clearDb(): void {
  const database = initDb();
  database.exec('DELETE FROM detections');
}

export function insertDetection(detection: Detection): void {
  const database = initDb();
  
  const stmt = database.prepare(`
    INSERT OR REPLACE INTO detections 
    (id, name, description, query, source_type, mitre_ids, logsource_category, 
     logsource_product, logsource_service, severity, status, author, 
     date_created, date_modified, refs, falsepositives, tags, file_path, raw_yaml)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(
    detection.id,
    detection.name,
    detection.description,
    detection.query,
    detection.source_type,
    JSON.stringify(detection.mitre_ids),
    detection.logsource_category,
    detection.logsource_product,
    detection.logsource_service,
    detection.severity,
    detection.status,
    detection.author,
    detection.date_created,
    detection.date_modified,
    JSON.stringify(detection.references),
    JSON.stringify(detection.falsepositives),
    JSON.stringify(detection.tags),
    detection.file_path,
    detection.raw_yaml
  );
}

function rowToDetection(row: Record<string, unknown>): Detection {
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string || '',
    query: row.query as string || '',
    source_type: row.source_type as 'sigma' | 'splunk_escu',
    mitre_ids: JSON.parse(row.mitre_ids as string || '[]'),
    logsource_category: row.logsource_category as string | null,
    logsource_product: row.logsource_product as string | null,
    logsource_service: row.logsource_service as string | null,
    severity: row.severity as string | null,
    status: row.status as string | null,
    author: row.author as string | null,
    date_created: row.date_created as string | null,
    date_modified: row.date_modified as string | null,
    references: JSON.parse(row.refs as string || '[]'),
    falsepositives: JSON.parse(row.falsepositives as string || '[]'),
    tags: JSON.parse(row.tags as string || '[]'),
    file_path: row.file_path as string,
    raw_yaml: row.raw_yaml as string,
  };
}

export function searchDetections(query: string, limit: number = 50): Detection[] {
  const database = initDb();
  
  // Use FTS5 for search
  const stmt = database.prepare(`
    SELECT d.* FROM detections d
    JOIN detections_fts fts ON d.rowid = fts.rowid
    WHERE detections_fts MATCH ?
    ORDER BY rank
    LIMIT ?
  `);
  
  const rows = stmt.all(query, limit) as Record<string, unknown>[];
  return rows.map(rowToDetection);
}

export function getDetectionById(id: string): Detection | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE id = ?');
  const row = stmt.get(id) as Record<string, unknown> | undefined;
  
  return row ? rowToDetection(row) : null;
}

export function listDetections(limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listBySource(sourceType: 'sigma' | 'splunk_escu', limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE source_type = ? ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(sourceType, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByMitre(techniqueId: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  // Search in JSON array
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE mitre_ids LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%"${techniqueId}"%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByLogsource(
  category?: string,
  product?: string,
  service?: string,
  limit: number = 100,
  offset: number = 0
): Detection[] {
  const database = initDb();
  
  let sql = 'SELECT * FROM detections WHERE 1=1';
  const params: (string | number)[] = [];
  
  if (category) {
    sql += ' AND logsource_category = ?';
    params.push(category);
  }
  if (product) {
    sql += ' AND logsource_product = ?';
    params.push(product);
  }
  if (service) {
    sql += ' AND logsource_service = ?';
    params.push(service);
  }
  
  sql += ' ORDER BY name LIMIT ? OFFSET ?';
  params.push(limit, offset);
  
  const stmt = database.prepare(sql);
  const rows = stmt.all(...params) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listBySeverity(level: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE severity = ? ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(level, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function getStats(): IndexStats {
  const database = initDb();
  
  const total = (database.prepare('SELECT COUNT(*) as count FROM detections').get() as { count: number }).count;
  const sigma = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'sigma'").get() as { count: number }).count;
  const splunk = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'splunk_escu'").get() as { count: number }).count;
  
  // Count by severity
  const severityRows = database.prepare(`
    SELECT severity, COUNT(*) as count FROM detections 
    WHERE severity IS NOT NULL 
    GROUP BY severity
  `).all() as { severity: string; count: number }[];
  
  const by_severity: Record<string, number> = {};
  for (const row of severityRows) {
    by_severity[row.severity] = row.count;
  }
  
  // Count by logsource product
  const productRows = database.prepare(`
    SELECT logsource_product, COUNT(*) as count FROM detections 
    WHERE logsource_product IS NOT NULL 
    GROUP BY logsource_product
    ORDER BY count DESC
    LIMIT 20
  `).all() as { logsource_product: string; count: number }[];
  
  const by_logsource_product: Record<string, number> = {};
  for (const row of productRows) {
    by_logsource_product[row.logsource_product] = row.count;
  }
  
  // Count detections with MITRE mappings
  const mitre_coverage = (database.prepare(`
    SELECT COUNT(*) as count FROM detections 
    WHERE mitre_ids != '[]' AND mitre_ids IS NOT NULL
  `).get() as { count: number }).count;
  
  return {
    total,
    sigma,
    splunk_escu: splunk,
    by_severity,
    by_logsource_product,
    mitre_coverage,
  };
}

export function getRawYaml(id: string): string | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT raw_yaml FROM detections WHERE id = ?');
  const row = stmt.get(id) as { raw_yaml: string } | undefined;
  
  return row?.raw_yaml || null;
}

export function dbExists(): boolean {
  return existsSync(DB_PATH);
}

export function getDetectionCount(): number {
  if (!dbExists()) return 0;
  const database = initDb();
  return (database.prepare('SELECT COUNT(*) as count FROM detections').get() as { count: number }).count;
}
