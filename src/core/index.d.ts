export type Category = 'tokens' | 'passwords' | 'cookies' | 'emails' | 'phones' | 'ipAddresses' | 'userPaths' | 'custom';
export type Action = 'label' | 'mask' | 'remove' | 'replace';
export interface Policy { enabled?: boolean; action?: Action; replacement?: string }
export interface Credential { name: string; value: string; action?: Action; replacement?: string }
export interface Config {
  version?: 1;
  action?: Action;
  replacement?: string;
  categories?: Partial<Record<Category, Policy>>;
  sensitiveKeys?: string[];
  credentials?: Credential[];
}
export interface Finding { category: Category; start: number; end: number; outputStart: number; outputEnd: number; action: Action }
export interface Result { text: string; findings: Finding[]; summary: Partial<Record<Category, number>>; total: number }
export const CATEGORY_NAMES: readonly Category[];
export const DEFAULT_CONFIG: Readonly<Config>;
export function normalizeConfig(config?: Config): Config;
export function createSanitizer(config?: Config): { sanitize(text: string): Result };
export function sanitize(text: string, config?: Config): Result;
