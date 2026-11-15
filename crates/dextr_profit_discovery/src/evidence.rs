//! Доказательная основа обнаружения экономических возможностей.
//!
//! Слой хранит происхождение фактов и попытки опровержения гипотез.
//! Наличие ссылки на источник не означает истинность утверждения:
//! независимая проверка качества источника остаётся отдельной задачей.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::{EconomicMap, OpportunityHypothesis};

/// Тип происхождения доказательного материала.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EvidenceSourceKind {
    Primary,
    Secondary,
    Derived,
    UserSupplied,
    Other(String),
}

/// Алгоритм контрольного отпечатка содержимого.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DigestAlgorithm {
    Sha256,
    Blake3,
}

/// Неизменяемая ссылка на доказательный материал.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecord {
    pub id: String,
    pub source_uri: String,
    pub publisher: String,
    pub source_kind: EvidenceSourceKind,
    pub digest_algorithm: DigestAlgorithm,
    /// Контрольный отпечаток содержимого в шестнадцатеричном виде.
    pub content_digest_hex: String,
    /// Время публикации источника в Unix milliseconds, если известно.
    pub published_at_unix_ms: Option<u64>,
    /// Время получения материала системой в Unix milliseconds.
    pub captured_at_unix_ms: u64,
    /// Ограничения, пробелы и известные смещения источника.
    pub limitations: Vec<String>,
}

impl EvidenceRecord {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.id.trim().is_empty()
            || self.source_uri.trim().is_empty()
            || self.publisher.trim().is_empty()
        {
            return Err(EvidenceError::EmptyRequiredField);
        }
        if self.content_digest_hex.len() != 64
            || !self
                .content_digest_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(EvidenceError::InvalidDigest);
        }
        if self
            .published_at_unix_ms
            .is_some_and(|published| published > self.captured_at_unix_ms)
        {
            return Err(EvidenceError::PublicationAfterCapture);
        }
        Ok(())
    }
}

/// Наблюдаемый факт, привязанный к экономическому объекту и источникам.
///
/// value_scaled хранит целое число в заранее объявленном масштабе.
/// Например, value_scaled=12345 и scale=100 означают 123,45 единицы.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedFact {
    pub id: String,
    pub subject_id: String,
    pub metric: String,
    pub value_scaled: i128,
    pub scale: u64,
    pub unit: String,
    pub observed_at_unix_ms: u64,
    pub evidence_ids: Vec<String>,
}

impl ObservedFact {
    fn validate(&self) -> Result<(), EvidenceError> {
        if self.id.trim().is_empty()
            || self.subject_id.trim().is_empty()
            || self.metric.trim().is_empty()
            || self.unit.trim().is_empty()
        {
            return Err(EvidenceError::EmptyRequiredField);
        }
        if self.scale == 0 {
            return Err(EvidenceError::ZeroScale);
        }
        if self.evidence_ids.is_empty() {
            return Err(EvidenceError::FactWithoutEvidence);
        }
        Ok(())
    }
}

/// Результат попытки независимого опровержения гипотезы.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FalsificationOutcome {
    Refuted,
    NotRefuted,
    Inconclusive,
}

/// Зафиксированная попытка опровержения или проверки.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FalsificationAttempt {
    pub id: String,
    pub hypothesis_id: String,
    pub method: String,
    pub outcome: FalsificationOutcome,
    pub evidence_ids: Vec<String>,
    pub notes: String,
}

impl FalsificationAttempt {
    fn validate(&self) -> Result<(), EvidenceError> {
        if self.id.trim().is_empty()
            || self.hypothesis_id.trim().is_empty()
            || self.method.trim().is_empty()
        {
            return Err(EvidenceError::EmptyRequiredField);
        }
        if self.evidence_ids.is_empty() {
            return Err(EvidenceError::AttemptWithoutEvidence);
        }
        Ok(())
    }
}

/// Журнал доказательств, наблюдений и попыток опровержения.
///
/// Записи не перезаписываются по идентификатору: повторное добавление
/// возвращает ошибку. Для исправления создаётся новая запись с новым ID.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvidenceLedger {
    evidence: BTreeMap<String, EvidenceRecord>,
    facts: BTreeMap<String, ObservedFact>,
    falsifications: BTreeMap<String, FalsificationAttempt>,
    registered_hypotheses: BTreeSet<String>,
}

impl EvidenceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_evidence(&mut self, record: EvidenceRecord) -> Result<(), EvidenceError> {
        record.validate()?;
        if self.evidence.contains_key(&record.id) {
            return Err(EvidenceError::DuplicateEvidence(record.id));
        }
        self.evidence.insert(record.id.clone(), record);
        Ok(())
    }

    pub fn add_fact(&mut self, map: &EconomicMap, fact: ObservedFact) -> Result<(), EvidenceError> {
        fact.validate()?;
        if map.node(&fact.subject_id).is_none() {
            return Err(EvidenceError::UnknownSubject(fact.subject_id));
        }
        if self.facts.contains_key(&fact.id) {
            return Err(EvidenceError::DuplicateFact(fact.id));
        }
        self.ensure_evidence_refs(&fact.evidence_ids)?;
        self.facts.insert(fact.id.clone(), fact);
        Ok(())
    }

    pub fn register_hypothesis(
        &mut self,
        map: &EconomicMap,
        hypothesis: &OpportunityHypothesis,
    ) -> Result<(), EvidenceError> {
        hypothesis
            .validate_against(map)
            .map_err(|_| EvidenceError::InvalidHypothesis(hypothesis.id.clone()))?;
        if !self.registered_hypotheses.insert(hypothesis.id.clone()) {
            return Err(EvidenceError::DuplicateHypothesis(hypothesis.id.clone()));
        }
        Ok(())
    }

    pub fn add_falsification(
        &mut self,
        attempt: FalsificationAttempt,
    ) -> Result<(), EvidenceError> {
        attempt.validate()?;
        if !self.registered_hypotheses.contains(&attempt.hypothesis_id) {
            return Err(EvidenceError::UnknownHypothesis(attempt.hypothesis_id));
        }
        if self.falsifications.contains_key(&attempt.id) {
            return Err(EvidenceError::DuplicateAttempt(attempt.id));
        }
        self.ensure_evidence_refs(&attempt.evidence_ids)?;
        self.falsifications.insert(attempt.id.clone(), attempt);
        Ok(())
    }

    fn ensure_evidence_refs(&self, ids: &[String]) -> Result<(), EvidenceError> {
        for id in ids {
            if !self.evidence.contains_key(id) {
                return Err(EvidenceError::UnknownEvidence(id.clone()));
            }
        }
        Ok(())
    }

    /// Последовательный доступ ко всем наблюдаемым фактам журнала.
    pub fn facts(&self) -> impl Iterator<Item = &ObservedFact> {
        self.facts.values()
    }

    pub fn evidence(&self, id: &str) -> Option<&EvidenceRecord> {
        self.evidence.get(id)
    }

    pub fn fact(&self, id: &str) -> Option<&ObservedFact> {
        self.facts.get(id)
    }

    pub fn falsification(&self, id: &str) -> Option<&FalsificationAttempt> {
        self.falsifications.get(id)
    }

    pub fn facts_for_subject<'a>(
        &'a self,
        subject_id: &'a str,
    ) -> impl Iterator<Item = &'a ObservedFact> + 'a {
        self.facts
            .values()
            .filter(move |fact| fact.subject_id == subject_id)
    }

    pub fn facts_for_metric<'a>(
        &'a self,
        subject_id: &'a str,
        metric: &'a str,
        unit: &'a str,
    ) -> impl Iterator<Item = &'a ObservedFact> + 'a {
        self.facts.values().filter(move |fact| {
            fact.subject_id == subject_id && fact.metric == metric && fact.unit == unit
        })
    }

    pub fn falsifications_for<'a>(
        &'a self,
        hypothesis_id: &'a str,
    ) -> impl Iterator<Item = &'a FalsificationAttempt> + 'a {
        self.falsifications
            .values()
            .filter(move |attempt| attempt.hypothesis_id == hypothesis_id)
    }

    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    pub fn fact_count(&self) -> usize {
        self.facts.len()
    }

    pub fn falsification_count(&self) -> usize {
        self.falsifications.len()
    }
}

/// Ошибки доказательного слоя.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceError {
    EmptyRequiredField,
    InvalidDigest,
    PublicationAfterCapture,
    ZeroScale,
    FactWithoutEvidence,
    AttemptWithoutEvidence,
    DuplicateEvidence(String),
    DuplicateFact(String),
    DuplicateAttempt(String),
    UnknownEvidence(String),
    UnknownSubject(String),
    InvalidHypothesis(String),
    DuplicateHypothesis(String),
    UnknownHypothesis(String),
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyRequiredField => write!(formatter, "обязательное поле пусто"),
            Self::InvalidDigest => write!(
                formatter,
                "контрольный отпечаток должен содержать 64 hex-символа"
            ),
            Self::PublicationAfterCapture => {
                write!(formatter, "дата публикации позже даты получения")
            }
            Self::ZeroScale => write!(formatter, "масштаб наблюдения должен быть больше нуля"),
            Self::FactWithoutEvidence => {
                write!(formatter, "факт не содержит ссылок на доказательства")
            }
            Self::AttemptWithoutEvidence => {
                write!(formatter, "попытка проверки не содержит доказательств")
            }
            Self::DuplicateEvidence(id) => {
                write!(formatter, "повторная запись доказательства: {id}")
            }
            Self::DuplicateFact(id) => write!(formatter, "повторная запись факта: {id}"),
            Self::DuplicateAttempt(id) => write!(formatter, "повторная попытка проверки: {id}"),
            Self::UnknownEvidence(id) => write!(formatter, "доказательство не найдено: {id}"),
            Self::UnknownSubject(id) => write!(formatter, "экономический объект не найден: {id}"),
            Self::InvalidHypothesis(id) => write!(formatter, "гипотеза не прошла проверку: {id}"),
            Self::DuplicateHypothesis(id) => {
                write!(formatter, "гипотеза уже зарегистрирована: {id}")
            }
            Self::UnknownHypothesis(id) => write!(formatter, "гипотеза не зарегистрирована: {id}"),
        }
    }
}

impl std::error::Error for EvidenceError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EconomicMap, EconomicNode, ValueForm};

    fn map() -> EconomicMap {
        let mut map = EconomicMap::new();
        map.add_node(
            EconomicNode::new(
                "asset-1",
                "Тестовый актив",
                ValueForm::Other("актив".into()),
            )
            .unwrap(),
        )
        .unwrap();
        map
    }

    fn evidence(id: &str) -> EvidenceRecord {
        EvidenceRecord {
            id: id.into(),
            source_uri: "https://example.org/report".into(),
            publisher: "Независимый источник".into(),
            source_kind: EvidenceSourceKind::Primary,
            digest_algorithm: DigestAlgorithm::Sha256,
            content_digest_hex: "a".repeat(64),
            published_at_unix_ms: Some(1_000),
            captured_at_unix_ms: 2_000,
            limitations: vec!["Тестовый источник".into()],
        }
    }

    fn fact(id: &str) -> ObservedFact {
        ObservedFact {
            id: id.into(),
            subject_id: "asset-1".into(),
            metric: "net_flow".into(),
            value_scaled: 12_345,
            scale: 100,
            unit: "USD".into(),
            observed_at_unix_ms: 1_500,
            evidence_ids: vec!["e1".into()],
        }
    }

    #[test]
    fn stores_evidence_and_fact_with_provenance() {
        let mut ledger = EvidenceLedger::new();
        ledger.add_evidence(evidence("e1")).unwrap();
        ledger.add_fact(&map(), fact("f1")).unwrap();

        assert_eq!(ledger.evidence_count(), 1);
        assert_eq!(ledger.fact_count(), 1);
        assert_eq!(ledger.fact("f1").unwrap().value_scaled, 12_345);
        assert_eq!(ledger.fact("f1").unwrap().scale, 100);
    }

    #[test]
    fn rejects_fact_without_known_evidence() {
        let mut ledger = EvidenceLedger::new();
        assert_eq!(
            ledger.add_fact(&map(), fact("f1")),
            Err(EvidenceError::UnknownEvidence("e1".into()))
        );
    }

    #[test]
    fn rejects_fact_for_unknown_economic_subject() {
        let mut ledger = EvidenceLedger::new();
        ledger.add_evidence(evidence("e1")).unwrap();
        let mut unknown = fact("f1");
        unknown.subject_id = "missing".into();

        assert_eq!(
            ledger.add_fact(&map(), unknown),
            Err(EvidenceError::UnknownSubject("missing".into()))
        );
    }

    #[test]
    fn rejects_duplicate_evidence_instead_of_overwriting_history() {
        let mut ledger = EvidenceLedger::new();
        ledger.add_evidence(evidence("e1")).unwrap();

        assert_eq!(
            ledger.add_evidence(evidence("e1")),
            Err(EvidenceError::DuplicateEvidence("e1".into()))
        );
    }

    #[test]
    fn rejects_invalid_digest() {
        let mut invalid = evidence("e1");
        invalid.content_digest_hex = "not-a-digest".into();

        assert_eq!(invalid.validate(), Err(EvidenceError::InvalidDigest));
    }

    fn hypothesis() -> crate::OpportunityHypothesis {
        crate::OpportunityHypothesis {
            id: "hyp-1".into(),
            title: "Проверяемая гипотеза".into(),
            description: "Тест".into(),
            node_ids: vec!["asset-1".into(), "asset-2".into()],
            relation_ids: vec!["r-missing".into()],
            estimate: crate::ProfitEstimate {
                currency: crate::CurrencyCode::new("USD").unwrap(),
                gross_revenue_minor: 100,
                direct_costs_minor: 10,
                operating_costs_minor: 10,
                financing_costs_minor: 0,
                tax_costs_minor: 0,
                downside_loss_minor: 10,
                probability_bps: 5_000,
                capital_required_minor: 100,
                opportunity_cost_minor: 0,
                period_days: 30,
            },
        }
    }

    #[test]
    fn records_falsification_attempts_with_evidence() {
        let mut ledger = EvidenceLedger::new();
        ledger.add_evidence(evidence("e1")).unwrap();
        let mut map = map();
        map.add_node(
            EconomicNode::new(
                "asset-2",
                "Связанный актив",
                ValueForm::Other("актив".into()),
            )
            .unwrap(),
        )
        .unwrap();
        map.add_relation(
            crate::EconomicRelation::new(
                "r-missing",
                "asset-1",
                "asset-2",
                crate::RelationKind::Enables,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        ledger.register_hypothesis(&map, &hypothesis()).unwrap();
        let attempt = FalsificationAttempt {
            id: "test-1".into(),
            hypothesis_id: "hyp-1".into(),
            method: "Независимый пересчёт".into(),
            outcome: FalsificationOutcome::Refuted,
            evidence_ids: vec!["e1".into()],
            notes: "Контрпример опроверг исходное предположение".into(),
        };
        ledger.add_falsification(attempt).unwrap();

        let stored = ledger.falsifications_for("hyp-1").next().unwrap();
        assert_eq!(stored.outcome, FalsificationOutcome::Refuted);
    }

    #[test]
    fn refuses_falsification_for_unregistered_hypothesis() {
        let mut ledger = EvidenceLedger::new();
        ledger.add_evidence(evidence("e1")).unwrap();
        let attempt = FalsificationAttempt {
            id: "test-unknown".into(),
            hypothesis_id: "unknown".into(),
            method: "Проверка".into(),
            outcome: FalsificationOutcome::Inconclusive,
            evidence_ids: vec!["e1".into()],
            notes: String::new(),
        };
        assert_eq!(
            ledger.add_falsification(attempt),
            Err(EvidenceError::UnknownHypothesis("unknown".into()))
        );
    }

    #[test]
    fn refuses_falsification_attempt_without_evidence() {
        let mut ledger = EvidenceLedger::new();
        let attempt = FalsificationAttempt {
            id: "test-1".into(),
            hypothesis_id: "hyp-1".into(),
            method: "Проверка".into(),
            outcome: FalsificationOutcome::Inconclusive,
            evidence_ids: Vec::new(),
            notes: String::new(),
        };

        assert_eq!(
            ledger.add_falsification(attempt),
            Err(EvidenceError::AttemptWithoutEvidence)
        );
    }

    #[test]
    fn filters_facts_by_metric_and_unit() {
        let mut ledger = EvidenceLedger::new();
        ledger.add_evidence(evidence("e1")).unwrap();
        ledger.add_fact(&map(), fact("f1")).unwrap();
        let mut other = fact("f2");
        other.unit = "EUR".into();
        ledger.add_fact(&map(), other).unwrap();

        assert_eq!(
            ledger
                .facts_for_metric("asset-1", "net_flow", "USD")
                .count(),
            1
        );
    }
}
