/**
 * Pagination abstraction and memory-exhaustion guard for Bank Eghtesad Novin APIs.
 */

export interface PageParams {
  page?: number;
  limit?: number;
  offset?: number;
  length?: number;
}

export interface PaginationGuardOptions {
  maxPages?: number;
  maxTotalItems?: number;
}

export const DEFAULT_PAGINATION_LIMIT = 20;
export const MAX_PAGINATION_PAGES = 50;
export const MAX_TOTAL_ITEMS = 2000;

/**
 * Standardized pagination fetcher that iterates across pages with a hard upper bound
 * to guarantee termination and protect against infinite loops or memory leaks.
 */
export async function collectAllPages<T>(
  fetchPage: (pageIndex: number, pageSize: number) => Promise<{ items: T[]; totalRecords?: number }>,
  options: PaginationGuardOptions = {}
): Promise<T[]> {
  const maxPages = options.maxPages ?? MAX_PAGINATION_PAGES;
  const maxItems = options.maxTotalItems ?? MAX_TOTAL_ITEMS;
  const pageSize = DEFAULT_PAGINATION_LIMIT;

  const collected: T[] = [];
  let page = 0;

  while (page < maxPages && collected.length < maxItems) {
    const res = await fetchPage(page, pageSize);
    const items = res.items || [];

    if (items.length === 0) {
      break;
    }

    collected.push(...items);

    if (res.totalRecords !== undefined && collected.length >= res.totalRecords) {
      break;
    }

    if (items.length < pageSize) {
      // Last page received
      break;
    }

    page++;
  }

  return collected;
}

