#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import {
  searchDetections,
  getDetectionById,
  listDetections,
  listBySource,
  listByMitre,
  listByLogsource,
  listBySeverity,
  listByCve,
  listByAnalyticStory,
  listByProcessName,
  listByDetectionType,
  listByDataSource,
  listByMitreTactic,
  listByKqlCategory,
  listByKqlTag,
  listByKqlDatasource,
  getStats,
  getRawYaml,
  getDbPath,
  initDb,
  recreateDb,
  searchStories,
  getStoryByName,
  listStories,
  listStoriesByCategory,
  getTechniqueIds,
  generateNavigatorLayer,
  analyzeCoverage,
  identifyGaps,
  suggestDetections,
} from './db.js';
import { indexDetections, needsIndexing } from './indexer.js';

// Parse comma-separated paths from env var
function parsePaths(envVar: string | undefined): string[] {
  if (!envVar) return [];
  return envVar.split(',').map(p => p.trim()).filter(p => p.length > 0);
}

// Get configured paths from environment
const SIGMA_PATHS = parsePaths(process.env.SIGMA_PATHS);
const SPLUNK_PATHS = parsePaths(process.env.SPLUNK_PATHS);
const ELASTIC_PATHS = parsePaths(process.env.ELASTIC_PATHS);
const STORY_PATHS = parsePaths(process.env.STORY_PATHS);
const KQL_PATHS = parsePaths(process.env.KQL_PATHS);

// Auto-index on startup if paths are configured and DB is empty
function autoIndex(): void {
  if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
    return;
  }
  
  initDb();
  
  if (needsIndexing()) {
    console.error('[security-detections-mcp] Auto-indexing detections...');
    const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
    let msg = `[security-detections-mcp] Indexed ${result.total} detections (${result.sigma_indexed} Sigma, ${result.splunk_indexed} Splunk, ${result.elastic_indexed} Elastic, ${result.kql_indexed} KQL)`;
    if (result.stories_indexed > 0) {
      msg += `, ${result.stories_indexed} stories`;
    }
    console.error(msg);
  }
}

// Create MCP server
const server = new Server(
  {
    name: 'security-detections-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Define available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'search',
        description: 'Full-text search across all detection fields (name, description, query, MITRE IDs, tags, CVEs, analytic stories, process names, file paths, registry paths)',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (FTS5 syntax supported). Examples: "powershell.exe", "CVE-2024", "DLL sideloading", "web server"',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 50)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_by_id',
        description: 'Get a single detection by its ID',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Detection ID (UUID for Sigma, or Splunk detection ID)',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'list_all',
        description: 'List all detections with pagination',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
        },
      },
      {
        name: 'list_by_source',
        description: 'List detections filtered by source type',
        inputSchema: {
          type: 'object',
          properties: {
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Source type to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['source_type'],
        },
      },
      {
        name: 'list_by_mitre',
        description: 'List detections that map to a specific MITRE ATT&CK technique',
        inputSchema: {
          type: 'object',
          properties: {
            technique_id: {
              type: 'string',
              description: 'MITRE ATT&CK technique ID (e.g., T1059.001)',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['technique_id'],
        },
      },
      {
        name: 'list_by_logsource',
        description: 'List Sigma detections filtered by logsource (category, product, or service)',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Logsource category (e.g., process_creation, network_connection)',
            },
            product: {
              type: 'string',
              description: 'Logsource product (e.g., windows, linux, aws)',
            },
            service: {
              type: 'string',
              description: 'Logsource service (e.g., sysmon, security, powershell)',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
        },
      },
      {
        name: 'list_by_severity',
        description: 'List detections filtered by severity level',
        inputSchema: {
          type: 'object',
          properties: {
            level: {
              type: 'string',
              enum: ['informational', 'low', 'medium', 'high', 'critical'],
              description: 'Severity level to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['level'],
        },
      },
      {
        name: 'list_by_cve',
        description: 'List detections that cover a specific CVE vulnerability',
        inputSchema: {
          type: 'object',
          properties: {
            cve_id: {
              type: 'string',
              description: 'CVE ID (e.g., CVE-2024-27198, CVE-2021-44228)',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['cve_id'],
        },
      },
      {
        name: 'list_by_analytic_story',
        description: 'List Splunk detections that belong to a specific analytic story (e.g., "Ransomware", "Data Destruction")',
        inputSchema: {
          type: 'object',
          properties: {
            story: {
              type: 'string',
              description: 'Analytic story name or partial match (e.g., "Ransomware", "Windows Persistence")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['story'],
        },
      },
      {
        name: 'list_by_process_name',
        description: 'List detections that reference a specific process name (e.g., "powershell.exe", "w3wp.exe", "cmd.exe")',
        inputSchema: {
          type: 'object',
          properties: {
            process_name: {
              type: 'string',
              description: 'Process name to search for (e.g., "powershell.exe", "cmd.exe", "nginx.exe")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['process_name'],
        },
      },
      {
        name: 'list_by_detection_type',
        description: 'List detections by type (TTP, Anomaly, Hunting, Correlation)',
        inputSchema: {
          type: 'object',
          properties: {
            detection_type: {
              type: 'string',
              enum: ['TTP', 'Anomaly', 'Hunting', 'Correlation'],
              description: 'Detection type to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['detection_type'],
        },
      },
      {
        name: 'list_by_data_source',
        description: 'List detections that use a specific data source (e.g., "Sysmon", "Windows Security", "process_creation")',
        inputSchema: {
          type: 'object',
          properties: {
            data_source: {
              type: 'string',
              description: 'Data source to search for (e.g., "Sysmon", "Windows Security", "process_creation")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['data_source'],
        },
      },
      {
        name: 'list_by_mitre_tactic',
        description: 'List detections by MITRE ATT&CK tactic (e.g., "execution", "persistence", "credential-access")',
        inputSchema: {
          type: 'object',
          properties: {
            tactic: {
              type: 'string',
              enum: ['reconnaissance', 'resource-development', 'initial-access', 'execution', 
                     'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
                     'discovery', 'lateral-movement', 'collection', 'command-and-control', 
                     'exfiltration', 'impact'],
              description: 'MITRE ATT&CK tactic to filter by',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['tactic'],
        },
      },
      {
        name: 'list_by_kql_category',
        description: 'List KQL detections filtered by category (e.g., "Defender For Endpoint", "Azure Active Directory", "Threat Hunting")',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'KQL category derived from folder path (e.g., "Defender For Endpoint", "DFIR", "Sentinel")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['category'],
        },
      },
      {
        name: 'list_by_kql_tag',
        description: 'List KQL detections filtered by tag (e.g., "ransomware", "hunting", "ti-feed")',
        inputSchema: {
          type: 'object',
          properties: {
            tag: {
              type: 'string',
              description: 'Tag to filter by (e.g., "ransomware", "dfir", "apt")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['tag'],
        },
      },
      {
        name: 'list_by_kql_datasource',
        description: 'List KQL detections that use a specific Microsoft data source (e.g., "DeviceProcessEvents", "SigninLogs", "EmailEvents")',
        inputSchema: {
          type: 'object',
          properties: {
            data_source: {
              type: 'string',
              description: 'Microsoft KQL table name (e.g., "DeviceProcessEvents", "AADSignInEventsBeta", "CloudAppEvents")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['data_source'],
        },
      },
      {
        name: 'search_stories',
        description: 'Search analytic stories by narrative, description, or name. Stories provide rich context about threat campaigns and detection strategies.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query for stories (e.g., "ransomware encryption", "credential theft", "persistence")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 20)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_story',
        description: 'Get detailed information about a specific analytic story by name',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Story name (e.g., "Ransomware", "Windows Persistence Techniques")',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'list_stories',
        description: 'List all analytic stories with pagination',
        inputSchema: {
          type: 'object',
          properties: {
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
        },
      },
      {
        name: 'list_stories_by_category',
        description: 'List analytic stories by category (e.g., "Malware", "Adversary Tactics", "Abuse")',
        inputSchema: {
          type: 'object',
          properties: {
            category: {
              type: 'string',
              description: 'Story category (e.g., "Malware", "Adversary Tactics", "Abuse", "Cloud Security")',
            },
            limit: {
              type: 'number',
              description: 'Max results to return (default 100)',
            },
            offset: {
              type: 'number',
              description: 'Offset for pagination (default 0)',
            },
          },
          required: ['category'],
        },
      },
      {
        name: 'get_stats',
        description: 'Get statistics about the indexed detections and stories',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'rebuild_index',
        description: 'Force re-index all detections and stories from configured paths',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_raw_yaml',
        description: 'Get the original YAML content for a detection',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Detection ID',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'get_technique_ids',
        description: 'Get ONLY unique MITRE technique IDs (lightweight - no full detection data). Use this for Navigator layer generation or coverage analysis.',
        inputSchema: {
          type: 'object',
          properties: {
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type',
            },
            tactic: {
              type: 'string',
              enum: ['reconnaissance', 'resource-development', 'initial-access', 'execution', 
                     'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
                     'discovery', 'lateral-movement', 'collection', 'command-and-control', 
                     'exfiltration', 'impact'],
              description: 'Filter by MITRE tactic',
            },
            severity: {
              type: 'string',
              enum: ['informational', 'low', 'medium', 'high', 'critical'],
              description: 'Filter by severity',
            },
          },
        },
      },
      {
        name: 'generate_navigator_layer',
        description: 'Generate a MITRE ATT&CK Navigator layer JSON directly from indexed detections. Returns ready-to-use layer file.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Layer name (e.g., "Elastic Initial Access Coverage")',
            },
            description: {
              type: 'string',
              description: 'Layer description',
            },
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type',
            },
            tactic: {
              type: 'string',
              enum: ['reconnaissance', 'resource-development', 'initial-access', 'execution', 
                     'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
                     'discovery', 'lateral-movement', 'collection', 'command-and-control', 
                     'exfiltration', 'impact'],
              description: 'Filter by MITRE tactic',
            },
            severity: {
              type: 'string',
              enum: ['informational', 'low', 'medium', 'high', 'critical'],
              description: 'Filter by severity',
            },
          },
          required: ['name'],
        },
      },
      {
        name: 'analyze_coverage',
        description: 'Get coverage analysis with stats by tactic, top covered techniques, and weak spots. Returns summary data, not raw detections. Use this instead of listing detections and processing manually.',
        inputSchema: {
          type: 'object',
          properties: {
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional - analyzes all if not specified)',
            },
          },
        },
      },
      {
        name: 'identify_gaps',
        description: 'Identify detection gaps based on a threat profile (ransomware, apt, initial-access, persistence, credential-access, defense-evasion). Returns prioritized gaps with recommendations.',
        inputSchema: {
          type: 'object',
          properties: {
            threat_profile: {
              type: 'string',
              enum: ['ransomware', 'apt', 'initial-access', 'persistence', 'credential-access', 'defense-evasion'],
              description: 'Threat profile to analyze gaps against',
            },
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional)',
            },
          },
          required: ['threat_profile'],
        },
      },
      {
        name: 'suggest_detections',
        description: 'Get detection suggestions for a specific technique. Returns existing detections, required data sources, and detection ideas.',
        inputSchema: {
          type: 'object',
          properties: {
            technique_id: {
              type: 'string',
              description: 'MITRE technique ID (e.g., T1059.001, T1547.001)',
            },
            source_type: {
              type: 'string',
              enum: ['sigma', 'splunk_escu', 'elastic', 'kql'],
              description: 'Filter by source type (optional)',
            },
          },
          required: ['technique_id'],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  try {
    switch (name) {
      case 'search': {
        const query = args?.query as string;
        const limit = (args?.limit as number) || 50;
        
        if (!query) {
          return { content: [{ type: 'text', text: 'Error: query is required' }] };
        }
        
        const results = searchDetections(query, limit);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'get_by_id': {
        const id = args?.id as string;
        
        if (!id) {
          return { content: [{ type: 'text', text: 'Error: id is required' }] };
        }
        
        const detection = getDetectionById(id);
        if (!detection) {
          return { content: [{ type: 'text', text: `Detection not found: ${id}` }] };
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(detection, null, 2),
          }],
        };
      }
      
      case 'list_all': {
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        const results = listDetections(limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_source': {
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic';
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!sourceType) {
          return { content: [{ type: 'text', text: 'Error: source_type is required' }] };
        }
        
        const results = listBySource(sourceType, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_mitre': {
        const techniqueId = args?.technique_id as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!techniqueId) {
          return { content: [{ type: 'text', text: 'Error: technique_id is required' }] };
        }
        
        const results = listByMitre(techniqueId, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_logsource': {
        const category = args?.category as string | undefined;
        const product = args?.product as string | undefined;
        const service = args?.service as string | undefined;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        const results = listByLogsource(category, product, service, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_severity': {
        const level = args?.level as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!level) {
          return { content: [{ type: 'text', text: 'Error: level is required' }] };
        }
        
        const results = listBySeverity(level, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_cve': {
        const cveId = args?.cve_id as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!cveId) {
          return { content: [{ type: 'text', text: 'Error: cve_id is required' }] };
        }
        
        const results = listByCve(cveId, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_analytic_story': {
        const story = args?.story as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!story) {
          return { content: [{ type: 'text', text: 'Error: story is required' }] };
        }
        
        const results = listByAnalyticStory(story, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_process_name': {
        const processName = args?.process_name as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!processName) {
          return { content: [{ type: 'text', text: 'Error: process_name is required' }] };
        }
        
        const results = listByProcessName(processName, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_detection_type': {
        const detectionType = args?.detection_type as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!detectionType) {
          return { content: [{ type: 'text', text: 'Error: detection_type is required' }] };
        }
        
        const results = listByDetectionType(detectionType, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_data_source': {
        const dataSource = args?.data_source as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!dataSource) {
          return { content: [{ type: 'text', text: 'Error: data_source is required' }] };
        }
        
        const results = listByDataSource(dataSource, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_mitre_tactic': {
        const tactic = args?.tactic as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!tactic) {
          return { content: [{ type: 'text', text: 'Error: tactic is required' }] };
        }
        
        const results = listByMitreTactic(tactic, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_kql_category': {
        const category = args?.category as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!category) {
          return { content: [{ type: 'text', text: 'Error: category is required' }] };
        }
        
        const results = listByKqlCategory(category, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_kql_tag': {
        const tag = args?.tag as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!tag) {
          return { content: [{ type: 'text', text: 'Error: tag is required' }] };
        }
        
        const results = listByKqlTag(tag, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_by_kql_datasource': {
        const dataSource = args?.data_source as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!dataSource) {
          return { content: [{ type: 'text', text: 'Error: data_source is required' }] };
        }
        
        const results = listByKqlDatasource(dataSource, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'search_stories': {
        const query = args?.query as string;
        const limit = (args?.limit as number) || 20;
        
        if (!query) {
          return { content: [{ type: 'text', text: 'Error: query is required' }] };
        }
        
        const results = searchStories(query, limit);
        if (results.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'No stories found. Stories are optional - set STORY_PATHS env var to index them.',
            }],
          };
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'get_story': {
        const storyName = args?.name as string;
        
        if (!storyName) {
          return { content: [{ type: 'text', text: 'Error: name is required' }] };
        }
        
        const story = getStoryByName(storyName);
        if (!story) {
          return { content: [{ type: 'text', text: `Story not found: ${storyName}. Stories are optional - set STORY_PATHS env var to index them.` }] };
        }
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(story, null, 2),
          }],
        };
      }
      
      case 'list_stories': {
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        const results = listStories(limit, offset);
        if (results.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'No stories indexed. Stories are optional - set STORY_PATHS env var to index them.',
            }],
          };
        }
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'list_stories_by_category': {
        const category = args?.category as string;
        const limit = (args?.limit as number) || 100;
        const offset = (args?.offset as number) || 0;
        
        if (!category) {
          return { content: [{ type: 'text', text: 'Error: category is required' }] };
        }
        
        const results = listStoriesByCategory(category, limit, offset);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(results, null, 2),
          }],
        };
      }
      
      case 'get_stats': {
        const stats = getStats();
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(stats, null, 2),
          }],
        };
      }
      
      case 'rebuild_index': {
        if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0 && ELASTIC_PATHS.length === 0 && KQL_PATHS.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'Error: No paths configured. Set SIGMA_PATHS, SPLUNK_PATHS, ELASTIC_PATHS, and/or KQL_PATHS environment variables.',
            }],
          };
        }
        
        // Recreate DB to apply schema changes
        recreateDb();
        
        const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS, STORY_PATHS, ELASTIC_PATHS, KQL_PATHS);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              message: 'Index rebuilt successfully',
              ...result,
              stories_note: STORY_PATHS.length === 0 ? 'No STORY_PATHS configured - stories not indexed' : undefined,
              elastic_note: ELASTIC_PATHS.length === 0 ? 'No ELASTIC_PATHS configured - Elastic rules not indexed' : undefined,
              kql_note: KQL_PATHS.length === 0 ? 'No KQL_PATHS configured - KQL queries not indexed' : undefined,
              db_path: getDbPath(),
            }, null, 2),
          }],
        };
      }
      
      case 'get_raw_yaml': {
        const id = args?.id as string;
        
        if (!id) {
          return { content: [{ type: 'text', text: 'Error: id is required' }] };
        }
        
        const yaml = getRawYaml(id);
        if (!yaml) {
          return { content: [{ type: 'text', text: `Detection not found: ${id}` }] };
        }
        
        return {
          content: [{
            type: 'text',
            text: yaml,
          }],
        };
      }
      
      case 'get_technique_ids': {
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        const tactic = args?.tactic as string | undefined;
        const severity = args?.severity as string | undefined;
        
        const techniqueIds = getTechniqueIds({
          source_type: sourceType,
          tactic,
          severity,
        });
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              count: techniqueIds.length,
              technique_ids: techniqueIds,
            }, null, 2),
          }],
        };
      }
      
      case 'generate_navigator_layer': {
        const name = args?.name as string;
        const description = args?.description as string | undefined;
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        const tactic = args?.tactic as string | undefined;
        const severity = args?.severity as string | undefined;
        
        if (!name) {
          return { content: [{ type: 'text', text: 'Error: name is required' }] };
        }
        
        const layer = generateNavigatorLayer({
          name,
          description,
          source_type: sourceType,
          tactic,
          severity,
        });
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(layer, null, 2),
          }],
        };
      }
      
      case 'analyze_coverage': {
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        
        const report = analyzeCoverage(sourceType);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(report, null, 2),
          }],
        };
      }
      
      case 'identify_gaps': {
        const threatProfile = args?.threat_profile as string;
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        
        if (!threatProfile) {
          return { content: [{ type: 'text', text: 'Error: threat_profile is required' }] };
        }
        
        const gaps = identifyGaps(threatProfile, sourceType);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(gaps, null, 2),
          }],
        };
      }
      
      case 'suggest_detections': {
        const techniqueId = args?.technique_id as string;
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu' | 'elastic' | undefined;
        
        if (!techniqueId) {
          return { content: [{ type: 'text', text: 'Error: technique_id is required' }] };
        }
        
        const suggestions = suggestDetections(techniqueId, sourceType);
        
        return {
          content: [{
            type: 'text',
            text: JSON.stringify(suggestions, null, 2),
          }],
        };
      }
      
      default:
        return {
          content: [{
            type: 'text',
            text: `Unknown tool: ${name}`,
          }],
        };
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      content: [{
        type: 'text',
        text: `Error: ${message}`,
      }],
    };
  }
});

// Main entry point
async function main() {
  // Auto-index on startup
  autoIndex();
  
  // Start MCP server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error('[security-detections-mcp] Server started');
}

main().catch((error) => {
  console.error('[security-detections-mcp] Fatal error:', error);
  process.exit(1);
});
