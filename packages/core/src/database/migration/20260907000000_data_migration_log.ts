import { sql } from "drizzle-orm"
import { Effect } from "effect"
import { Database } from "../database"
import { DataMigrationTable } from "../../data-migration.sql"
import type { DatabaseMigration } from "../migration"

/**
 * Data-migration bookkeeping table for one-off, code-driven data fixes that
 * don't fit the schema-migration model (e.g. backfilling a new column, fixing
 * legacy rows). Each row records a unique migration `name` and the time it
 * was applied — use {@link isDataMigrated} as the guard before running the
 * body. Mirrors how upstream Drizzle projects track ad-hoc migrations.
 */
export default {
  id: "20260907000000_data_migration_log",
  up(tx) {
    return Effect.gen(function* () {
      yield* tx.run(`
        CREATE TABLE IF NOT EXISTS \`data_migration\` (
          \`name\` text NOT NULL,
          \`time_completed\` integer NOT NULL,
          PRIMARY KEY (\`name\`)
        );
      `)
    })
  },
} satisfies DatabaseMigration.Migration

/**
 * Returns true if the named data migration has already run. Migrations are
 * idempotent — re-running one whose name is in the table is a no-op.
 */
export const isDataMigrated = (name: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    const rows = yield* db.select().from(DataMigrationTable).where(sql`${DataMigrationTable.name} = ${name}`).limit(1)
    return rows.length > 0
  })

/**
 * Mark a data migration as complete. Call this AT THE END of the migration
 * body — if the body throws, the row isn't written and a future run will
 * retry. Mirrors the "sentinel" pattern used by graphbit's bootstrap
 * (`Vendors.bootstrapGraphbitPython`).
 */
export const markDataMigrated = (name: string) =>
  Effect.gen(function* () {
    const { db } = yield* Database.Service
    yield* db
      .insert(DataMigrationTable)
      .values({ name, time_completed: Math.floor(Date.now() / 1000) })
      .onConflictDoNothing()
  })
