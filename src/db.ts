import Database from 'better-sqlite3';
import { homedir } from 'os';
import { join } from 'path';
import { mkdirSync, existsSync, unlinkSync } from 'fs';
import type { Detection, IndexStats, AnalyticStory } from './types.js';

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
  
  // Create main detections table with all enhanced fields
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
      raw_yaml TEXT,
      cves TEXT,
      analytic_stories TEXT,
      data_sources TEXT,
      detection_type TEXT,
      asset_type TEXT,
      security_domain TEXT,
      process_names TEXT,
      file_paths TEXT,
      registry_paths TEXT,
      mitre_tactics TEXT
    )
  `);
  
  // Create FTS5 virtual table for full-text search with all searchable fields
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS detections_fts USING fts5(
      id,
      name,
      description,
      query,
      mitre_ids,
      tags,
      cves,
      analytic_stories,
      data_sources,
      process_names,
      file_paths,
      registry_paths,
      mitre_tactics,
      content='detections',
      content_rowid='rowid'
    )
  `);
  
  // Create triggers to keep FTS in sync
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ai AFTER INSERT ON detections BEGIN
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_ad AFTER DELETE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS detections_au AFTER UPDATE ON detections BEGIN
      INSERT INTO detections_fts(detections_fts, rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.query, OLD.mitre_ids, OLD.tags, OLD.cves, OLD.analytic_stories, OLD.data_sources, OLD.process_names, OLD.file_paths, OLD.registry_paths, OLD.mitre_tactics);
      INSERT INTO detections_fts(rowid, id, name, description, query, mitre_ids, tags, cves, analytic_stories, data_sources, process_names, file_paths, registry_paths, mitre_tactics)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.query, NEW.mitre_ids, NEW.tags, NEW.cves, NEW.analytic_stories, NEW.data_sources, NEW.process_names, NEW.file_paths, NEW.registry_paths, NEW.mitre_tactics);
    END
  `);
  
  // Create indexes for common queries
  db.exec(`CREATE INDEX IF NOT EXISTS idx_source_type ON detections(source_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_severity ON detections(severity)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_product ON detections(logsource_product)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logsource_category ON detections(logsource_category)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_detection_type ON detections(detection_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_asset_type ON detections(asset_type)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_security_domain ON detections(security_domain)`);
  
  // Create stories table (optional - provides rich context for analytic stories)
  db.exec(`
    CREATE TABLE IF NOT EXISTS stories (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      narrative TEXT,
      author TEXT,
      date TEXT,
      version INTEGER,
      status TEXT,
      refs TEXT,
      category TEXT,
      usecase TEXT,
      detection_names TEXT
    )
  `);
  
  // Create FTS5 for stories (narrative is key for semantic search!)
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS stories_fts USING fts5(
      id,
      name,
      description,
      narrative,
      category,
      usecase,
      content='stories',
      content_rowid='rowid'
    )
  `);
  
  // Triggers for stories FTS
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS stories_ai AFTER INSERT ON stories BEGIN
      INSERT INTO stories_fts(rowid, id, name, description, narrative, category, usecase)
      VALUES (NEW.rowid, NEW.id, NEW.name, NEW.description, NEW.narrative, NEW.category, NEW.usecase);
    END
  `);
  
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS stories_ad AFTER DELETE ON stories BEGIN
      INSERT INTO stories_fts(stories_fts, rowid, id, name, description, narrative, category, usecase)
      VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.description, OLD.narrative, OLD.category, OLD.usecase);
    END
  `);
  
  db.exec(`CREATE INDEX IF NOT EXISTS idx_story_category ON stories(category)`);
  
  return db;
}

export function clearDb(): void {
  const database = initDb();
  database.exec('DELETE FROM detections');
}

// Force recreation of the database (needed when schema changes)
export function recreateDb(): void {
  if (db) {
    db.close();
    db = null;
  }
  if (existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
  }
}

export function insertDetection(detection: Detection): void {
  const database = initDb();
  
  const stmt = database.prepare(`
    INSERT OR REPLACE INTO detections 
    (id, name, description, query, source_type, mitre_ids, logsource_category, 
     logsource_product, logsource_service, severity, status, author, 
     date_created, date_modified, refs, falsepositives, tags, file_path, raw_yaml,
     cves, analytic_stories, data_sources, detection_type, asset_type, security_domain,
     process_names, file_paths, registry_paths, mitre_tactics)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    detection.raw_yaml,
    JSON.stringify(detection.cves),
    JSON.stringify(detection.analytic_stories),
    JSON.stringify(detection.data_sources),
    detection.detection_type,
    detection.asset_type,
    detection.security_domain,
    JSON.stringify(detection.process_names),
    JSON.stringify(detection.file_paths),
    JSON.stringify(detection.registry_paths),
    JSON.stringify(detection.mitre_tactics)
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
    cves: JSON.parse(row.cves as string || '[]'),
    analytic_stories: JSON.parse(row.analytic_stories as string || '[]'),
    data_sources: JSON.parse(row.data_sources as string || '[]'),
    detection_type: row.detection_type as string | null,
    asset_type: row.asset_type as string | null,
    security_domain: row.security_domain as string | null,
    process_names: JSON.parse(row.process_names as string || '[]'),
    file_paths: JSON.parse(row.file_paths as string || '[]'),
    registry_paths: JSON.parse(row.registry_paths as string || '[]'),
    mitre_tactics: JSON.parse(row.mitre_tactics as string || '[]'),
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

export function listBySource(sourceType: 'sigma' | 'splunk_escu' | 'elastic', limit: number = 100, offset: number = 0): Detection[] {
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

// New query methods for enhanced fields

export function listByCve(cveId: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE cves LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%"${cveId}"%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByAnalyticStory(story: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE analytic_stories LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%${story}%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByProcessName(processName: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE process_names LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%${processName}%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByDetectionType(detectionType: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM detections WHERE detection_type = ? ORDER BY name LIMIT ? OFFSET ?');
  const rows = stmt.all(detectionType, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByDataSource(dataSource: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE data_sources LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%${dataSource}%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function listByMitreTactic(tactic: string, limit: number = 100, offset: number = 0): Detection[] {
  const database = initDb();
  
  const stmt = database.prepare(`
    SELECT * FROM detections 
    WHERE mitre_tactics LIKE ? 
    ORDER BY name 
    LIMIT ? OFFSET ?
  `);
  const rows = stmt.all(`%"${tactic}"%`, limit, offset) as Record<string, unknown>[];
  
  return rows.map(rowToDetection);
}

export function getStats(): IndexStats {
  const database = initDb();
  
  const total = (database.prepare('SELECT COUNT(*) as count FROM detections').get() as { count: number }).count;
  const sigma = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'sigma'").get() as { count: number }).count;
  const splunk = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'splunk_escu'").get() as { count: number }).count;
  const elastic = (database.prepare("SELECT COUNT(*) as count FROM detections WHERE source_type = 'elastic'").get() as { count: number }).count;
  
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
  
  // Count detections with CVE mappings
  const cve_coverage = (database.prepare(`
    SELECT COUNT(*) as count FROM detections 
    WHERE cves != '[]' AND cves IS NOT NULL
  `).get() as { count: number }).count;
  
  // Count by MITRE tactic
  const tacticRows = database.prepare(`
    SELECT mitre_tactics FROM detections 
    WHERE mitre_tactics != '[]' AND mitre_tactics IS NOT NULL
  `).all() as { mitre_tactics: string }[];
  
  const by_mitre_tactic: Record<string, number> = {};
  for (const row of tacticRows) {
    const tactics = JSON.parse(row.mitre_tactics) as string[];
    for (const tactic of tactics) {
      by_mitre_tactic[tactic] = (by_mitre_tactic[tactic] || 0) + 1;
    }
  }
  
  // Count by detection type
  const typeRows = database.prepare(`
    SELECT detection_type, COUNT(*) as count FROM detections 
    WHERE detection_type IS NOT NULL 
    GROUP BY detection_type
  `).all() as { detection_type: string; count: number }[];
  
  const by_detection_type: Record<string, number> = {};
  for (const row of typeRows) {
    by_detection_type[row.detection_type] = row.count;
  }
  
  // Count stories (optional table)
  let stories_count = 0;
  const by_story_category: Record<string, number> = {};
  try {
    stories_count = (database.prepare('SELECT COUNT(*) as count FROM stories').get() as { count: number }).count;
    
    const categoryRows = database.prepare(`
      SELECT category, COUNT(*) as count FROM stories 
      WHERE category IS NOT NULL 
      GROUP BY category
    `).all() as { category: string; count: number }[];
    
    for (const row of categoryRows) {
      by_story_category[row.category] = row.count;
    }
  } catch {
    // Stories table might not exist or be empty - that's fine
  }
  
  return {
    total,
    sigma,
    splunk_escu: splunk,
    elastic,
    by_severity,
    by_logsource_product,
    mitre_coverage,
    cve_coverage,
    by_mitre_tactic,
    by_detection_type,
    stories_count,
    by_story_category,
    by_elastic_index: {},  // Could be populated if needed
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

// Story-related functions

export function insertStory(story: AnalyticStory): void {
  const database = initDb();
  
  const stmt = database.prepare(`
    INSERT OR REPLACE INTO stories 
    (id, name, description, narrative, author, date, version, status, refs, category, usecase, detection_names)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(
    story.id,
    story.name,
    story.description,
    story.narrative,
    story.author,
    story.date,
    story.version,
    story.status,
    JSON.stringify(story.references),
    story.category,
    story.usecase,
    JSON.stringify(story.detection_names)
  );
}

function rowToStory(row: Record<string, unknown>): AnalyticStory {
  return {
    id: row.id as string,
    name: row.name as string,
    description: row.description as string || '',
    narrative: row.narrative as string || '',
    author: row.author as string | null,
    date: row.date as string | null,
    version: row.version as number | null,
    status: row.status as string | null,
    references: JSON.parse(row.refs as string || '[]'),
    category: row.category as string | null,
    usecase: row.usecase as string | null,
    detection_names: JSON.parse(row.detection_names as string || '[]'),
  };
}

export function getStoryByName(name: string): AnalyticStory | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM stories WHERE name = ?');
  const row = stmt.get(name) as Record<string, unknown> | undefined;
  
  return row ? rowToStory(row) : null;
}

export function getStoryById(id: string): AnalyticStory | null {
  const database = initDb();
  
  const stmt = database.prepare('SELECT * FROM stories WHERE id = ?');
  const row = stmt.get(id) as Record<string, unknown> | undefined;
  
  return row ? rowToStory(row) : null;
}

export function searchStories(query: string, limit: number = 20): AnalyticStory[] {
  const database = initDb();
  
  try {
    const stmt = database.prepare(`
      SELECT s.* FROM stories s
      JOIN stories_fts fts ON s.rowid = fts.rowid
      WHERE stories_fts MATCH ?
      ORDER BY rank
      LIMIT ?
    `);
    
    const rows = stmt.all(query, limit) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    // If no stories indexed, return empty
    return [];
  }
}

export function listStories(limit: number = 100, offset: number = 0): AnalyticStory[] {
  const database = initDb();
  
  try {
    const stmt = database.prepare('SELECT * FROM stories ORDER BY name LIMIT ? OFFSET ?');
    const rows = stmt.all(limit, offset) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    return [];
  }
}

export function listStoriesByCategory(category: string, limit: number = 100, offset: number = 0): AnalyticStory[] {
  const database = initDb();
  
  try {
    const stmt = database.prepare('SELECT * FROM stories WHERE category = ? ORDER BY name LIMIT ? OFFSET ?');
    const rows = stmt.all(category, limit, offset) as Record<string, unknown>[];
    return rows.map(rowToStory);
  } catch {
    return [];
  }
}

export function getStoryCount(): number {
  const database = initDb();
  try {
    return (database.prepare('SELECT COUNT(*) as count FROM stories').get() as { count: number }).count;
  } catch {
    return 0;
  }
}
