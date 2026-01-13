import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import type { AnalyticStory, SplunkStoryYaml } from '../types.js';

export function parseStoryFile(filePath: string): AnalyticStory | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const story = parseYaml(content) as SplunkStoryYaml;
    
    // name and id are required
    if (!story.name || !story.id) {
      return null;
    }
    
    const analyticStory: AnalyticStory = {
      id: story.id,
      name: story.name,
      description: story.description || '',
      narrative: story.narrative || '',
      author: story.author || null,
      date: story.date || null,
      version: story.version || null,
      status: story.status || null,
      references: story.references || [],
      category: story.tags?.category?.[0] || null,
      usecase: story.tags?.usecase || null,
      detection_names: [], // Will be populated during indexing by linking detections
    };
    
    return analyticStory;
  } catch (err) {
    // Skip files that can't be parsed
    return null;
  }
}
