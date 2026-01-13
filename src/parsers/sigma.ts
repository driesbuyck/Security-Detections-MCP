import { readFileSync } from 'fs';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';
import { createHash } from 'crypto';
import type { Detection, SigmaRule } from '../types.js';

// Extract MITRE ATT&CK IDs from Sigma tags
// Tags like: attack.t1059.001, attack.execution, attack.s0154, attack.g0032
function extractMitreIds(tags: string[] | undefined): string[] {
  if (!tags) return [];
  
  const mitreIds: string[] = [];
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    // Match technique IDs: attack.t1234 or attack.t1234.001
    const techMatch = lower.match(/^attack\.t(\d{4}(?:\.\d{3})?)$/);
    if (techMatch) {
      mitreIds.push(`T${techMatch[1].toUpperCase()}`);
      continue;
    }
    // Match software IDs: attack.s1234
    const softMatch = lower.match(/^attack\.s(\d{4})$/);
    if (softMatch) {
      mitreIds.push(`S${softMatch[1]}`);
      continue;
    }
    // Match group IDs: attack.g1234
    const groupMatch = lower.match(/^attack\.g(\d{4})$/);
    if (groupMatch) {
      mitreIds.push(`G${groupMatch[1]}`);
    }
  }
  return mitreIds;
}

// Generate a stable ID from file path and title if no UUID present
function generateId(filePath: string, title: string): string {
  const hash = createHash('sha256')
    .update(`${filePath}:${title}`)
    .digest('hex')
    .substring(0, 32);
  return `sigma-${hash}`;
}

// Normalize falsepositives field (can be string or array)
function normalizeFalsePositives(fp: string | string[] | undefined): string[] {
  if (!fp) return [];
  if (typeof fp === 'string') return [fp];
  return fp;
}

export function parseSigmaFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = parseYaml(content) as SigmaRule;
    
    // title is required
    if (!rule.title) {
      return null;
    }
    
    // logsource and detection are required
    if (!rule.logsource || !rule.detection) {
      return null;
    }
    
    const id = rule.id || generateId(filePath, rule.title);
    
    const detection: Detection = {
      id,
      name: rule.title,
      description: rule.description || '',
      query: stringifyYaml(rule.detection),
      source_type: 'sigma',
      mitre_ids: extractMitreIds(rule.tags),
      logsource_category: rule.logsource.category || null,
      logsource_product: rule.logsource.product || null,
      logsource_service: rule.logsource.service || null,
      severity: rule.level || null,
      status: rule.status || null,
      author: rule.author || null,
      date_created: rule.date || null,
      date_modified: rule.modified || null,
      references: rule.references || [],
      falsepositives: normalizeFalsePositives(rule.falsepositives),
      tags: rule.tags || [],
      file_path: filePath,
      raw_yaml: content,
    };
    
    return detection;
  } catch (err) {
    // Skip files that can't be parsed
    return null;
  }
}
