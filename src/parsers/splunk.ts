import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import type { Detection, SplunkDetection } from '../types.js';

export function parseSplunkFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = parseYaml(content) as SplunkDetection;
    
    // name and id are required
    if (!rule.name || !rule.id) {
      return null;
    }
    
    // search is required
    if (!rule.search) {
      return null;
    }
    
    const detection: Detection = {
      id: rule.id,
      name: rule.name,
      description: rule.description || '',
      query: rule.search,
      source_type: 'splunk_escu',
      mitre_ids: rule.tags?.mitre_attack_id || [],
      logsource_category: null,
      logsource_product: null,
      logsource_service: null,
      severity: null, // Splunk ESCU doesn't have severity in same way
      status: rule.status || null,
      author: rule.author || null,
      date_created: rule.date || null,
      date_modified: null,
      references: rule.references || [],
      falsepositives: rule.known_false_positives ? [rule.known_false_positives] : [],
      tags: rule.tags?.analytic_story || [],
      file_path: filePath,
      raw_yaml: content,
    };
    
    return detection;
  } catch (err) {
    // Skip files that can't be parsed
    return null;
  }
}
