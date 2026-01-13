import { readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { parseSigmaFile } from './parsers/sigma.js';
import { parseSplunkFile } from './parsers/splunk.js';
import { clearDb, insertDetection, getDetectionCount } from './db.js';

// Recursively find all YAML files in a directory
function findYamlFiles(dir: string): string[] {
  const files: string[] = [];
  
  try {
    const entries = readdirSync(dir);
    
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      
      try {
        const stat = statSync(fullPath);
        
        if (stat.isDirectory()) {
          files.push(...findYamlFiles(fullPath));
        } else if (stat.isFile()) {
          const ext = extname(entry).toLowerCase();
          if (ext === '.yml' || ext === '.yaml') {
            files.push(fullPath);
          }
        }
      } catch {
        // Skip files we can't stat
      }
    }
  } catch {
    // Skip directories we can't read
  }
  
  return files;
}

export interface IndexResult {
  sigma_indexed: number;
  sigma_failed: number;
  splunk_indexed: number;
  splunk_failed: number;
  total: number;
}

export function indexDetections(sigmaPaths: string[], splunkPaths: string[]): IndexResult {
  // Clear existing data
  clearDb();
  
  let sigma_indexed = 0;
  let sigma_failed = 0;
  let splunk_indexed = 0;
  let splunk_failed = 0;
  
  // Index Sigma rules
  for (const basePath of sigmaPaths) {
    const files = findYamlFiles(basePath);
    
    for (const file of files) {
      const detection = parseSigmaFile(file);
      if (detection) {
        insertDetection(detection);
        sigma_indexed++;
      } else {
        sigma_failed++;
      }
    }
  }
  
  // Index Splunk ESCU detections
  for (const basePath of splunkPaths) {
    const files = findYamlFiles(basePath);
    
    for (const file of files) {
      const detection = parseSplunkFile(file);
      if (detection) {
        insertDetection(detection);
        splunk_indexed++;
      } else {
        splunk_failed++;
      }
    }
  }
  
  return {
    sigma_indexed,
    sigma_failed,
    splunk_indexed,
    splunk_failed,
    total: sigma_indexed + splunk_indexed,
  };
}

export function needsIndexing(): boolean {
  return getDetectionCount() === 0;
}
