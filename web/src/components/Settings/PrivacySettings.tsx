// src/components/Settings/PrivacySettings.tsx
//
// Privacy signal toggles + language selector — Arctic Signal design.

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
    presence: "privacy.presence",
    typing: "privacy.typing",
    deliveryReceipts: "privacy.deliveryReceipts",
    readReceipts: "privacy.readReceipts",
  };

  return (
    <section aria-labelledby="privacy-settings-title" className="iceq-settings-section">
      <h3 id="privacy-settings-title" className="text-sm font-semibold text-frozen">
        {i18n.t("privacy.title")}
      </h3>

      {/* Language */}
      <label className="iceq-settings-row" htmlFor="locale-select">
        <span className="text-sm text-frozen">{i18n.t("settings.language")}</span>
        <select
          id="locale-select"
          className="iceq-select w-32"
          value={i18n.locale}
          onChange={(event) => i18n.setLocale(event.target.value as Locale)}
        >
          <option value="en">{i18n.t("settings.english")}</option>
          <option value="tr">{i18n.t("settings.turkish")}</option>
        </select>
      </label>

      <div className="iceq-divider" />

      {/* Privacy toggles */}
      {Object.keys(labels).map((rawKey) => {
        const key = rawKey as keyof PrivacyValue;
        return (
          <label key={key} className="iceq-toggle">
            <input
              type="checkbox"
              checked={privacy[key]}
              onChange={() => toggle(key)}
            />
            <span className="iceq-toggle-track" />
            <span>{i18n.t(labels[key])}</span>
          </label>
        );
      })}

      <div className="iceq-divider" />

      {/* Disappearing messages */}
      <label className="iceq-settings-row" htmlFor="disappearing-duration">
        <span className="text-sm text-mist">{i18n.t("privacy.disappearing")}</span>
        <select
          id="disappearing-duration"
          className="iceq-select w-28"
          value={disappearing}
          onChange={(event) => {
            const next = Number(event.target.value);
            setDisappearing(next);
            saveDisappearingSeconds(next);
          }}
        >
          <option value={3600}>{i18n.t("privacy.oneHour")}</option>
          <option value={86400}>{i18n.t("privacy.oneDay")}</option>
          <option value={259200}>{i18n.t("privacy.threeDays")}</option>
          <option value={604800}>{i18n.t("privacy.sevenDays")}</option>
        </select>
      </label>

      <p className="text-xs text-mist-dim">{i18n.t("privacy.disappearingHelp")}</p>
    </section>
  );
}
