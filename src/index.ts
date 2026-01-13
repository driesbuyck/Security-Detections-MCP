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
  getStats,
  getRawYaml,
  getDbPath,
  initDb,
  dbExists,
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

// Auto-index on startup if paths are configured and DB is empty
function autoIndex(): void {
  if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0) {
    return;
  }
  
  initDb();
  
  if (needsIndexing()) {
    console.error('[security-detections-mcp] Auto-indexing detections...');
    const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS);
    console.error(`[security-detections-mcp] Indexed ${result.total} detections (${result.sigma_indexed} Sigma, ${result.splunk_indexed} Splunk ESCU)`);
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
        description: 'Full-text search across all detection fields (name, description, query, MITRE IDs, tags)',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Search query (FTS5 syntax supported)',
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
              enum: ['sigma', 'splunk_escu'],
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
        name: 'get_stats',
        description: 'Get statistics about the indexed detections',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'rebuild_index',
        description: 'Force re-index all detections from configured paths',
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
        const sourceType = args?.source_type as 'sigma' | 'splunk_escu';
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
        if (SIGMA_PATHS.length === 0 && SPLUNK_PATHS.length === 0) {
          return {
            content: [{
              type: 'text',
              text: 'Error: No paths configured. Set SIGMA_PATHS and/or SPLUNK_PATHS environment variables.',
            }],
          };
        }
        
        const result = indexDetections(SIGMA_PATHS, SPLUNK_PATHS);
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              message: 'Index rebuilt successfully',
              ...result,
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
