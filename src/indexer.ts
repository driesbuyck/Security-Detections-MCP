import { readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import { parseSigmaFile } from './parsers/sigma.js';
import { parseSplunkFile } from './parsers/splunk.js';
import { parseStoryFile } from './parsers/story.js';
import { parseElasticFile } from './parsers/elastic.js';
import { recreateDb, insertDetection, insertStory, getDetectionCount, initDb } from './db.js';

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

// Recursively find all TOML files in a directory (for Elastic rules)
function findTomlFiles(dir: string): string[] {
  const files: string[] = [];
  
  try {
    const entries = readdirSync(dir);
    
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      
      try {
        const stat = statSync(fullPath);
        
        if (stat.isDirectory()) {
          // Skip _deprecated directory
          if (entry !== '_deprecated') {
            files.push(...findTomlFiles(fullPath));
          }
        } else if (stat.isFile()) {
          const ext = extname(entry).toLowerCase();
          if (ext === '.toml') {
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
  elastic_indexed: number;
  elastic_failed: number;
  stories_indexed: number;
  stories_failed: number;
  total: number;
}

export function indexDetections(
  sigmaPaths: string[], 
  splunkPaths: string[],
  storyPaths: string[] = [],
  elasticPaths: string[] = []
): IndexResult {
  // Recreate DB to ensure schema is up to date
  recreateDb();
  initDb();
  
  let sigma_indexed = 0;
  let sigma_failed = 0;
  let splunk_indexed = 0;
  let splunk_failed = 0;
  let elastic_indexed = 0;
  let elastic_failed = 0;
  let stories_indexed = 0;
  let stories_failed = 0;
  
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
  
  // Index Elastic detection rules (TOML format)
  for (const basePath of elasticPaths) {
    const files = findTomlFiles(basePath);
    
    for (const file of files) {
      const detection = parseElasticFile(file);
      if (detection) {
        insertDetection(detection);
        elastic_indexed++;
      } else {
        elastic_failed++;
      }
    }
  }
  
  // Index Splunk Analytic Stories (optional)
  for (const basePath of storyPaths) {
    const files = findYamlFiles(basePath);
    
    for (const file of files) {
      const story = parseStoryFile(file);
      if (story) {
        insertStory(story);
        stories_indexed++;
      } else {
        stories_failed++;
      }
    }
  }
  
  return {
    sigma_indexed,
    sigma_failed,
    splunk_indexed,
    splunk_failed,
    elastic_indexed,
    elastic_failed,
    stories_indexed,
    stories_failed,
    total: sigma_indexed + splunk_indexed + elastic_indexed,
  };
}

export function needsIndexing(): boolean {
  return getDetectionCount() === 0;
}
