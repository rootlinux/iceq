import { useState } from "react";
import { useI18n, type Locale } from "../../i18n";
import { loadDisappearingSeconds, loadPrivacySettings, saveDisappearingSeconds, savePrivacySettings, type PrivacySettings as PrivacyValue } from "../../lib/privacySettings";

export function PrivacySettings(): JSX.Element {
  const i18n = useI18n();
  const [privacy, setPrivacy] = useState<PrivacyValue>(() => loadPrivacySettings());
  const [disappearing, setDisappearing] = useState(() => loadDisappearingSeconds());
  const toggle = (key: keyof PrivacyValue): void => {
    const next = { ...privacy, [key]: !privacy[key] };
    setPrivacy(next);
    savePrivacySettings(next);
  };
  const labels: Record<keyof PrivacyValue, Parameters<typeof i18n.t>[0]> = {
    presence: "privacy.presence", typing: "privacy.typing", deliveryReceipts: "privacy.deliveryReceipts", readReceipts: "privacy.readReceipts",
  };
  return (
    <section className="space-y-4" aria-labelledby="privacy-settings-title">
      <h3 id="privacy-settings-title">{i18n.t("privacy.title")}</h3>
      <label className="iceq-settings-row" htmlFor="locale-select">
        <span>{i18n.t("settings.language")}</span>
        <select id="locale-select" value={i18n.locale} onChange={(event) => i18n.setLocale(event.target.value as Locale)}>
          <option value="en">{i18n.t("settings.english")}</option><option value="tr">{i18n.t("settings.turkish")}</option>
        </select>
      </label>
      {Object.keys(labels).map((rawKey) => {
        const key = rawKey as keyof PrivacyValue;
        return <label key={key} className="iceq-toggle"><input type="checkbox" checked={privacy[key]} onChange={() => toggle(key)} />{i18n.t(labels[key])}</label>;
      })}
      <div className="iceq-settings-row">
        <label htmlFor="disappearing-duration">{i18n.t("privacy.disappearing")}</label>
        <select id="disappearing-duration" value={disappearing} onChange={(event) => { const next = Number(event.target.value); setDisappearing(next); saveDisappearingSeconds(next); }}>
          <option value={0}>{i18n.t("privacy.off")}</option><option value={3600}>{i18n.t("privacy.oneHour")}</option><option value={86400}>{i18n.t("privacy.oneDay")}</option><option value={604800}>{i18n.t("privacy.sevenDays")}</option><option value={2592000}>{i18n.t("privacy.thirtyDays")}</option>
        </select>
      </div>
      <p className="text-sm text-text-2">{i18n.t("privacy.disappearingHelp")}</p>
    </section>
  );
}

