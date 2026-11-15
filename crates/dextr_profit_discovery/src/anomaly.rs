//! Детерминированное обнаружение аномалий в наблюдаемых экономических фактах.
//!
//! Аномалия является сигналом для проверки, а не доказательством возможности.
//! Сравниваются только наблюдения одного объекта, метрики и единицы измерения.
//! Для каждой точки используются только предшествующие наблюдения.

use std::collections::{BTreeMap, BTreeSet};

use super::evidence::{EvidenceLedger, ObservedFact};

/// Параметры обнаружения аномалий.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnomalyConfig {
    /// Минимальное число исторических точек до оценки следующей точки.
    pub minimum_history: usize,
    /// Порог в единицах MAD. Значение 6 означает отклонение не менее 6 MAD.
    pub mad_multiplier: u32,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            minimum_history: 5,
            mad_multiplier: 6,
        }
    }
}

/// Направление отклонения относительно исторической медианы.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnomalyDirection {
    AboveBaseline,
    BelowBaseline,
}

/// Обнаруженное отклонение. Само по себе не подтверждает коммерческую ценность.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnomalyCandidate {
    pub subject_id: String,
    pub metric: String,
    pub unit: String,
    /// Делитель для восстановления исходного значения: value_scaled / scale.
    pub scale: u64,
    pub fact_id: String,
    pub observed_at_unix_ms: u64,
    pub observed_value_scaled: i128,
    pub baseline_median_scaled: i128,
    pub median_absolute_deviation_scaled: i128,
    pub absolute_deviation_scaled: i128,
    pub direction: AnomalyDirection,
    pub evidence_ids: Vec<String>,
}

/// Ошибки проверки входного ряда.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AnomalyError {
    InvalidConfiguration,
    DuplicateFactId(String),
    DuplicateTimestamp {
        subject_id: String,
        metric: String,
        timestamp: u64,
    },
    ArithmeticOverflow,
}

impl std::fmt::Display for AnomalyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfiguration => write!(f, "некорректные параметры обнаружения"),
            Self::DuplicateFactId(id) => write!(f, "повторный идентификатор факта: {id}"),
            Self::DuplicateTimestamp {
                subject_id,
                metric,
                timestamp,
            } => write!(
                f,
                "повторная временная отметка для {subject_id}/{metric}: {timestamp}"
            ),
            Self::ArithmeticOverflow => write!(f, "переполнение при статистическом расчёте"),
        }
    }
}

impl std::error::Error for AnomalyError {}

/// Находит аномалии по исторической медиане и медианному абсолютному отклонению.
///
/// Факты с разными единицами или масштабами не смешиваются. Ряд обрабатывается
/// в хронологическом порядке; текущая точка не входит в собственную базу сравнения.
/// При MAD=0 любое ненулевое отклонение помечается как кандидат, что позволяет
/// обнаружить единичный скачок в стабильном ряду.
pub fn detect_anomalies(
    facts: &[ObservedFact],
    config: AnomalyConfig,
) -> Result<Vec<AnomalyCandidate>, AnomalyError> {
    if config.minimum_history < 3 || config.mad_multiplier == 0 {
        return Err(AnomalyError::InvalidConfiguration);
    }

    let mut ids = BTreeSet::new();
    let mut groups: BTreeMap<(String, String, String, u64), Vec<&ObservedFact>> = BTreeMap::new();

    for fact in facts {
        if !ids.insert(fact.id.as_str()) {
            return Err(AnomalyError::DuplicateFactId(fact.id.clone()));
        }
        groups
            .entry((
                fact.subject_id.clone(),
                fact.metric.clone(),
                fact.unit.clone(),
                fact.scale,
            ))
            .or_default()
            .push(fact);
    }

    let mut anomalies = Vec::new();
    for ((subject_id, metric, unit, scale), mut series) in groups {
        series.sort_by(|a, b| {
            a.observed_at_unix_ms
                .cmp(&b.observed_at_unix_ms)
                .then_with(|| a.id.cmp(&b.id))
        });

        for pair in series.windows(2) {
            if pair[0].observed_at_unix_ms == pair[1].observed_at_unix_ms {
                return Err(AnomalyError::DuplicateTimestamp {
                    subject_id: subject_id.clone(),
                    metric: metric.clone(),
                    timestamp: pair[0].observed_at_unix_ms,
                });
            }
        }

        let mut history: Vec<i128> = Vec::with_capacity(series.len());
        for fact in series {
            if history.len() >= config.minimum_history {
                let baseline = median(&mut history.clone())?;
                let mut deviations = history
                    .iter()
                    .map(|value| {
                        value
                            .checked_sub(baseline)
                            .and_then(i128::checked_abs)
                            .ok_or(AnomalyError::ArithmeticOverflow)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mad = median(&mut deviations)?;
                let deviation = fact
                    .value_scaled
                    .checked_sub(baseline)
                    .and_then(i128::checked_abs)
                    .ok_or(AnomalyError::ArithmeticOverflow)?;
                let threshold = mad
                    .checked_mul(i128::from(config.mad_multiplier))
                    .ok_or(AnomalyError::ArithmeticOverflow)?;
                let is_anomaly = if mad == 0 {
                    deviation > 0
                } else {
                    deviation >= threshold
                };

                if is_anomaly {
                    anomalies.push(AnomalyCandidate {
                        subject_id: subject_id.clone(),
                        metric: metric.clone(),
                        unit: unit.clone(),
                        scale,
                        fact_id: fact.id.clone(),
                        observed_at_unix_ms: fact.observed_at_unix_ms,
                        observed_value_scaled: fact.value_scaled,
                        baseline_median_scaled: baseline,
                        median_absolute_deviation_scaled: mad,
                        absolute_deviation_scaled: deviation,
                        direction: if fact.value_scaled >= baseline {
                            AnomalyDirection::AboveBaseline
                        } else {
                            AnomalyDirection::BelowBaseline
                        },
                        evidence_ids: fact.evidence_ids.clone(),
                    });
                }
            }
            history.push(fact.value_scaled);
        }
    }

    anomalies.sort_by(|a, b| {
        a.observed_at_unix_ms
            .cmp(&b.observed_at_unix_ms)
            .then_with(|| a.subject_id.cmp(&b.subject_id))
            .then_with(|| a.metric.cmp(&b.metric))
            .then_with(|| a.fact_id.cmp(&b.fact_id))
    });
    Ok(anomalies)
}

/// Запускает детектор непосредственно по фактам доказательного журнала.
pub fn detect_ledger_anomalies(
    ledger: &EvidenceLedger,
    config: AnomalyConfig,
) -> Result<Vec<AnomalyCandidate>, AnomalyError> {
    let facts: Vec<ObservedFact> = ledger.facts().cloned().collect();
    detect_anomalies(&facts, config)
}

fn median(values: &mut [i128]) -> Result<i128, AnomalyError> {
    if values.is_empty() {
        return Err(AnomalyError::InvalidConfiguration);
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        Ok(values[middle])
    } else {
        let left = values[middle - 1];
        let right = values[middle];
        let halves = left / 2 + right / 2;
        let remainders = left % 2 + right % 2;
        halves
            .checked_add(remainders / 2)
            .ok_or(AnomalyError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(id: &str, value: i128, time: u64, unit: &str, scale: u64) -> ObservedFact {
        ObservedFact {
            id: id.into(),
            subject_id: "asset".into(),
            metric: "volume".into(),
            value_scaled: value,
            scale,
            unit: unit.into(),
            observed_at_unix_ms: time,
            evidence_ids: vec![format!("e-{id}")],
        }
    }

    #[test]
    fn detects_spike_after_sufficient_history() {
        let facts = vec![
            fact("f1", 100, 1, "USD", 1),
            fact("f2", 101, 2, "USD", 1),
            fact("f3", 99, 3, "USD", 1),
            fact("f4", 100, 4, "USD", 1),
            fact("f5", 100, 5, "USD", 1),
            fact("f6", 500, 6, "USD", 1),
        ];
        let found = detect_anomalies(&facts, AnomalyConfig::default()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].fact_id, "f6");
        assert_eq!(found[0].baseline_median_scaled, 100);
        assert_eq!(found[0].scale, 1);
        assert_eq!(found[0].direction, AnomalyDirection::AboveBaseline);
    }

    #[test]
    fn does_not_mix_units_or_scales() {
        let facts = vec![
            fact("a1", 10, 1, "USD", 1),
            fact("a2", 10, 2, "USD", 1),
            fact("a3", 10, 3, "USD", 1),
            fact("a4", 10, 4, "USD", 1),
            fact("a5", 10, 5, "USD", 1),
            fact("b1", 1000, 6, "EUR", 100),
        ];
        assert!(
            detect_anomalies(&facts, AnomalyConfig::default())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn flags_change_in_zero_mad_series() {
        let facts = vec![
            fact("f1", 7, 1, "units", 1),
            fact("f2", 7, 2, "units", 1),
            fact("f3", 7, 3, "units", 1),
            fact("f4", 7, 4, "units", 1),
            fact("f5", 7, 5, "units", 1),
            fact("f6", 8, 6, "units", 1),
        ];
        assert_eq!(
            detect_anomalies(&facts, AnomalyConfig::default())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_duplicate_timestamps_and_fact_ids() {
        let duplicate_time = vec![fact("a", 1, 1, "u", 1), fact("b", 2, 1, "u", 1)];
        assert!(matches!(
            detect_anomalies(
                &duplicate_time,
                AnomalyConfig {
                    minimum_history: 3,
                    mad_multiplier: 6
                }
            ),
            Err(AnomalyError::DuplicateTimestamp { .. })
        ));

        let duplicate_id = vec![fact("same", 1, 1, "u", 1), fact("same", 2, 2, "v", 1)];
        assert_eq!(
            detect_anomalies(
                &duplicate_id,
                AnomalyConfig {
                    minimum_history: 3,
                    mad_multiplier: 6
                }
            ),
            Err(AnomalyError::DuplicateFactId("same".into()))
        );
    }

    #[test]
    fn analyzes_facts_directly_from_evidence_ledger() {
        use super::super::{EconomicMap, EconomicNode, ValueForm};

        let mut map = EconomicMap::new();
        map.add_node(
            EconomicNode::new(
                "asset",
                "Экономический объект",
                ValueForm::Other("тест".into()),
            )
            .unwrap(),
        )
        .unwrap();

        let mut ledger = EvidenceLedger::new();
        for index in 1..=6 {
            let id = format!("f{index}");
            ledger
                .add_evidence(super::super::evidence::EvidenceRecord {
                    id: format!("e-{id}"),
                    source_uri: format!("https://example.invalid/{id}"),
                    publisher: "Тестовый источник".into(),
                    source_kind: super::super::evidence::EvidenceSourceKind::Primary,
                    digest_algorithm: super::super::evidence::DigestAlgorithm::Sha256,
                    content_digest_hex: "0".repeat(64),
                    published_at_unix_ms: None,
                    captured_at_unix_ms: index,
                    limitations: vec!["Синтетический тест".into()],
                })
                .unwrap();
            ledger
                .add_fact(
                    &map,
                    ObservedFact {
                        id: id.clone(),
                        subject_id: "asset".into(),
                        metric: "volume".into(),
                        value_scaled: if index == 6 { 500 } else { 100 },
                        scale: 100,
                        unit: "USD".into(),
                        observed_at_unix_ms: index,
                        evidence_ids: vec![format!("e-{id}")],
                    },
                )
                .unwrap();
        }

        let found = detect_ledger_anomalies(&ledger, AnomalyConfig::default()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].fact_id, "f6");
        assert_eq!(found[0].scale, 100);
    }

    #[test]
    fn rejects_invalid_configuration() {
        assert_eq!(
            detect_anomalies(
                &[],
                AnomalyConfig {
                    minimum_history: 2,
                    mad_multiplier: 6
                }
            ),
            Err(AnomalyError::InvalidConfiguration)
        );
    }
}
