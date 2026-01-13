// Unified detection schema - normalized from both Sigma and Splunk ESCU

export interface Detection {
  id: string;
  name: string;
  description: string;
  query: string; // detection logic (YAML for Sigma, SPL for Splunk)
  source_type: 'sigma' | 'splunk_escu';
  mitre_ids: string[];
  logsource_category: string | null;
  logsource_product: string | null;
  logsource_service: string | null;
  severity: string | null;
  status: string | null;
  author: string | null;
  date_created: string | null;
  date_modified: string | null;
  references: string[];
  falsepositives: string[];
  tags: string[];
  file_path: string;
  raw_yaml: string;
}

// Sigma rule structure based on official schema
export interface SigmaRule {
  title: string;
  id?: string;
  name?: string;
  status?: 'stable' | 'test' | 'experimental' | 'deprecated' | 'unsupported';
  description?: string;
  license?: string;
  author?: string;
  references?: string[];
  date?: string;
  modified?: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
    definition?: string;
  };
  detection: Record<string, unknown>;
  fields?: string[];
  falsepositives?: string | string[];
  level?: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  tags?: string[];
  related?: Array<{ id: string; type: string }>;
  scope?: string[];
  taxonomy?: string;
}

// Splunk ESCU detection structure
export interface SplunkDetection {
  name: string;
  id: string;
  version?: number;
  date?: string;
  author?: string;
  status?: string;
  type?: string;
  description?: string;
  data_source?: string[];
  search: string;
  how_to_implement?: string;
  known_false_positives?: string;
  references?: string[];
  tags?: {
    analytic_story?: string[];
    asset_type?: string;
    mitre_attack_id?: string[];
    product?: string[];
    security_domain?: string;
    [key: string]: unknown;
  };
}

export interface IndexStats {
  total: number;
  sigma: number;
  splunk_escu: number;
  by_severity: Record<string, number>;
  by_logsource_product: Record<string, number>;
  mitre_coverage: number;
}
