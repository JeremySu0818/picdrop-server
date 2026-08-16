export type ByteRangeResult =
  | { kind: 'none' }
  | { kind: 'invalid' }
  | { kind: 'range'; start: number; end: number };

export function parseByteRange(
  value: string | undefined,
  totalLength: number,
): ByteRangeResult {
  if (value === undefined) return { kind: 'none' };
  if (!Number.isSafeInteger(totalLength) || totalLength <= 0) {
    return { kind: 'invalid' };
  }

  const match = /^bytes=(\d*)-(\d*)$/.exec(value.trim());
  if (!match || (!match[1] && !match[2])) return { kind: 'invalid' };

  if (!match[1]) {
    const suffixLength = Number(match[2]);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) {
      return { kind: 'invalid' };
    }
    return {
      kind: 'range',
      start: Math.max(0, totalLength - suffixLength),
      end: totalLength - 1,
    };
  }

  const start = Number(match[1]);
  const requestedEnd = match[2] ? Number(match[2]) : totalLength - 1;
  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(requestedEnd) ||
    start < 0 ||
    start >= totalLength ||
    requestedEnd < start
  ) {
    return { kind: 'invalid' };
  }

  return {
    kind: 'range',
    start,
    end: Math.min(requestedEnd, totalLength - 1),
  };
}
