/**
 * Hackvertor Tag: pretty_json
 * Usage: <@pretty_json>{"name":"John","age":30}<@/pretty_json>
 */

output = JSON.stringify(JSON.parse(input), null, spacing)