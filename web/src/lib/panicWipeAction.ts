export async function runConfirmedPanicWipe(
  confirm: () => boolean,
  panicWipe: (pin?: string) => Promise<void>,
  pin?: string,
): Promise<boolean> {
  if (!confirm()) return false;
  await panicWipe(pin);
  return true;
}
