export async function runConfirmedPanicWipe(
  confirm: () => boolean,
  panicWipe: () => Promise<void>,
): Promise<boolean> {
  if (!confirm()) return false;
  await panicWipe();
  return true;
}
