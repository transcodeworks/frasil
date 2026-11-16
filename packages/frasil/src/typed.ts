/**
 * TypeScript types from an index's manifest: the JSON a Rust schema's `Schema::manifest` writes,
 * or the one an application writes by hand for `@frasil/client/index`.
 *
 * @module
 */

import { FrasilError } from "./errors.js";

/** A column of a manifest's table. */
interface ManifestColumn {
  readonly name: string;
  readonly kind: string;
  readonly nullable: boolean;
  readonly references?: string;
}

/** A table of a manifest. */
interface ManifestTable {
  readonly name: string;
  readonly source: string;
  readonly suggestions: boolean;
  readonly columns: readonly ManifestColumn[];
}

/** Each column kind's type, in a Records row and in a query's row. */
const kinds: { readonly [kind: string]: readonly [cell: string, sql: string] } = {
  integer: ["number | bigint", "number | bigint"],
  real: ["number", "number"],
  bool: ["boolean", "number"],
  text: ["string", "string"],
  bytes: ["Uint8Array", "Uint8Array"],
  time: ["number | bigint", "number | bigint"],
  ref: ["Uint8Array", "string"],
  rich_text: ["Uint8Array", "string"],
};

/** A table's name as a type's: `task_list` is `TaskList`. */
function typeName(name: string): string {
  return name
    .split(/[^A-Za-z0-9]+/)
    .filter((part) => part.length > 0)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
}

/** A property's name, quoted when it is not an identifier. */
function property(name: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) ? name : JSON.stringify(name);
}

/**
 * TypeScript declarations for a manifest's tables: for each table, an interface of its Records
 * row (`<Table>Row`, for `records.table<…>()`) and one of a query's row of it (`<Table>Query`,
 * with the built-in columns), and `Tables`, which names each table's row type.
 *
 * ```ts
 * writeFileSync("tables.d.ts", manifestToTypeScript(manifest));
 * ```
 */
export function manifestToTypeScript(manifest: string | object): string {
  const parsed = (typeof manifest === "string" ? JSON.parse(manifest) : manifest) as {
    format?: unknown;
    tables?: unknown;
  };
  if (parsed.format !== 1 || !Array.isArray(parsed.tables)) {
    throw new FrasilError("invalid_input", "This is not an index manifest of format 1.");
  }
  const tables = parsed.tables as ManifestTable[];
  const out = ["// Generated from an index manifest by manifestToTypeScript.", ""];
  for (const table of tables) {
    const name = typeName(table.name);
    const row: string[] = [];
    const query: string[] = [
      "  readonly _space: string;",
      "  readonly _key: string;",
      "  readonly _author: string | null;",
      "  readonly _changed_at: number | bigint | null;",
    ];
    if (table.suggestions) {
      query.push("  readonly _suggested: number;", "  readonly _suggestion: string;");
    }
    for (const column of table.columns) {
      const types = kinds[column.kind];
      if (types === undefined) {
        throw new FrasilError(
          "invalid_input",
          `${table.name}.${column.name} has a kind this package does not know: ${column.kind}`,
        );
      }
      const [cell, sql] = types;
      const key = property(column.name);
      row.push(`  readonly ${key}${column.nullable ? "?" : ""}: ${cell};`);
      query.push(`  readonly ${key}: ${sql}${column.nullable ? " | null" : ""};`);
    }
    out.push(
      `/** A row of \`${table.name}\` (fed by spaces of kind \`${table.source}\`), as Records holds it. */`,
      `export interface ${name}Row {`,
      ...row,
      "}",
      "",
      `/** A row of \`${table.name}\` as a query of the index gives it. */`,
      `export interface ${name}Query {`,
      ...query,
      "}",
      "",
    );
  }
  out.push("/** Each table's Records row type, by table name. */", "export interface Tables {");
  for (const table of tables) out.push(`  ${property(table.name)}: ${typeName(table.name)}Row;`);
  out.push("}", "");
  return out.join("\n");
}
