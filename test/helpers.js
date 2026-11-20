import { createDb, seed } from '../server/db.js';

/** 每个测试用例使用独立的内存数据库，避免相互污染。 */
export function freshDb() {
  const db = createDb(':memory:');
  seed(db);
  return db;
}

export const ORG = { HQ: 1, EAST: 2, NORTH: 3, SH: 4, HZ: 5, BJ: 6, TJ: 7 };
export const USER = { ADMIN: 1, ALICE: 2, BOB: 3, CAROL: 4 };
export const METRIC = { REVENUE: 1, ORDERS: 2, SALARY: 3, MARGIN: 4 };
