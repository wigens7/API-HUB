const { Pool } = require('pg');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined, max: 10, idleTimeoutMillis: 30000, connectionTimeoutMillis: 10000 });

/** Run fn inside a transaction bound to one tenant (ctx.businessId) or to the admin role (ctx.admin). */
async function scoped(ctx, fn) {
 if (!ctx.admin && !UUID_RE.test(String(ctx.businessId || ''))) { const e = new Error('Tenant context missing.'); e.status = 403; throw e; }
 const client = await pool.connect();
 try {
  await client.query('BEGIN');
  await client.query(`SET LOCAL ROLE ${ctx.admin ? 'zytrelix_admin' : 'zytrelix_tenant'}`);
  if (!ctx.admin) await client.query(`SELECT set_config('app.business_id', $1, true)`, [ctx.businessId]);
  const result = await fn(client);
  await client.query('COMMIT');
  return result;
 } catch (err) { await client.query('ROLLBACK').catch(() => {}); throw err; }
 finally { client.release(); }
}
module.exports = { pool, scoped, UUID_RE };
