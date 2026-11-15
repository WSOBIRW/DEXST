
//! Минимальное экономическое ядро Dexter Studio.
//!
//! Ядро описывает формы стоимости, отношения между ними и проверяемые
//! гипотезы о прибыли. Оно не подключается к финансовым площадкам и не
//! считает синтетические данные доказательством реальной доходности.

#![forbid(unsafe_code)]

pub mod anomaly;
pub use anomaly::{
    AnomalyCandidate, AnomalyConfig, AnomalyDirection, AnomalyError, detect_anomalies,
};

pub mod evidence;
pub use evidence::*;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Код валюты в формате ISO 4217 (три заглавные латинские буквы).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    pub fn new(value: impl Into<String>) -> Result<Self, DiscoveryError> {
        let value = value.into();
        if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(DiscoveryError::InvalidCurrencyCode(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Форма представления стоимости или экономического требования.
///
/// Платёжная карта намеренно не выделена как форма денег: сама карта
/// является инструментом доступа к счёту, кредиту или предоплаченному остатку.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ValueForm {
    Cash,
    BankDeposit,
    ElectronicMoney,
    CommodityMoney,
    DebtClaim,
    Equity,
    Bond,
    PaymentInstrument,
    Cryptocurrency,
    Stablecoin,
    CentralBankDigitalCurrency,
    NonFungibleToken,
    UtilityToken,
    SecurityToken,
    GovernanceToken,
    TokenizedRealWorldAsset,
    Derivative,
    InsuranceClaim,
    CarbonCredit,
    IntellectualPropertyRight,
    FutureRevenueRight,
    LoyaltyValue,
    ClearingUnit,
    Other(String),
}

/// Экономический объект: форма стоимости, участник, инфраструктура или актив.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EconomicNode {
    pub id: String,
    pub label: String,
    pub form: ValueForm,
}

impl EconomicNode {
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        form: ValueForm,
    ) -> Result<Self, DiscoveryError> {
        let id = id.into();
        let label = label.into();
        if id.trim().is_empty() || label.trim().is_empty() {
            return Err(DiscoveryError::EmptyIdentifierOrLabel);
        }
        Ok(Self { id, label, form })
    }
}

/// Тип отношения между экономическими объектами.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum RelationKind {
    ConvertsInto,
    Transfers,
    Represents,
    Secures,
    ClaimsAgainst,
    GeneratesCashFlow,
    RequiresSettlement,
    BearsRisk,
    Insures,
    ProvidesLiquidity,
    Finances,
    Owns,
    Governs,
    Restricts,
    Enables,
    Other(String),
}

/// Направленное отношение между двумя объектами.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EconomicRelation {
    pub id: String,
    pub from: String,
    pub to: String,
    pub kind: RelationKind,
    pub evidence_ref: Option<String>,
}

impl EconomicRelation {
    pub fn new(
        id: impl Into<String>,
        from: impl Into<String>,
        to: impl Into<String>,
        kind: RelationKind,
        evidence_ref: Option<String>,
    ) -> Result<Self, DiscoveryError> {
        let id = id.into();
        let from = from.into();
        let to = to.into();
        if id.trim().is_empty() || from.trim().is_empty() || to.trim().is_empty() {
            return Err(DiscoveryError::EmptyIdentifierOrLabel);
        }
        if from == to {
            return Err(DiscoveryError::SelfRelation(from));
        }
        Ok(Self {
            id,
            from,
            to,
            kind,
            evidence_ref,
        })
    }
}

/// Карта объектов и отношений. BTreeMap обеспечивает детерминированный порядок.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EconomicMap {
    nodes: BTreeMap<String, EconomicNode>,
    relations: BTreeMap<String, EconomicRelation>,
}

impl EconomicMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: EconomicNode) -> Result<(), DiscoveryError> {
        if self.nodes.contains_key(&node.id) {
            return Err(DiscoveryError::DuplicateNode(node.id));
        }
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    pub fn add_relation(&mut self, relation: EconomicRelation) -> Result<(), DiscoveryError> {
        if self.relations.contains_key(&relation.id) {
            return Err(DiscoveryError::DuplicateRelation(relation.id));
        }
        if !self.nodes.contains_key(&relation.from) {
            return Err(DiscoveryError::MissingNode(relation.from));
        }
        if !self.nodes.contains_key(&relation.to) {
            return Err(DiscoveryError::MissingNode(relation.to));
        }
        self.relations.insert(relation.id.clone(), relation);
        Ok(())
    }

    pub fn node(&self, id: &str) -> Option<&EconomicNode> {
        self.nodes.get(id)
    }

    pub fn relation(&self, id: &str) -> Option<&EconomicRelation> {
        self.relations.get(id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &EconomicNode> {
        self.nodes.values()
    }

    pub fn relations(&self) -> impl Iterator<Item = &EconomicRelation> {
        self.relations.values()
    }

    /// Находит направленные цепочки из двух отношений A → B → C.
    ///
    /// Это структурные кандидаты, а не готовые бизнес-гипотезы и не прогнозы прибыли.
    pub fn two_step_candidates(&self) -> Vec<StructuralCandidate> {
        let mut candidates = Vec::new();
        for first in self.relations.values() {
            for second in self.relations.values() {
                if first.id == second.id || first.to != second.from {
                    continue;
                }
                if first.from == second.to || first.from == first.to || second.from == second.to {
                    continue;
                }
                candidates.push(StructuralCandidate {
                    node_ids: vec![first.from.clone(), first.to.clone(), second.to.clone()],
                    relation_ids: vec![first.id.clone(), second.id.clone()],
                });
            }
        }
        candidates.sort();
        candidates.dedup();
        candidates
    }
}

/// Найденная структурная комбинация без утверждения о её прибыльности.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct StructuralCandidate {
    pub node_ids: Vec<String>,
    pub relation_ids: Vec<String>,
}

/// Проверяемая финансовая модель одной гипотезы.
///
/// Все денежные значения задаются в минимальных единицах указанной валюты
/// (например, центах). Все затраты и возможный убыток неотрицательны.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfitEstimate {
    pub currency: CurrencyCode,
    pub gross_revenue_minor: i128,
    pub direct_costs_minor: i128,
    pub operating_costs_minor: i128,
    pub financing_costs_minor: i128,
    pub tax_costs_minor: i128,
    pub downside_loss_minor: i128,
    /// Вероятность базового сценария в базисных пунктах: 10 000 = 100%.
    pub probability_bps: u16,
    pub capital_required_minor: i128,
    pub opportunity_cost_minor: i128,
    pub period_days: u32,
}

impl ProfitEstimate {
    fn validate(&self) -> Result<(), DiscoveryError> {
        let values = [
            ("выручка", self.gross_revenue_minor),
            ("прямые затраты", self.direct_costs_minor),
            ("операционные затраты", self.operating_costs_minor),
            ("стоимость финансирования", self.financing_costs_minor),
            ("налоги", self.tax_costs_minor),
            ("сценарный убыток", self.downside_loss_minor),
            ("необходимый капитал", self.capital_required_minor),
            (
                "альтернативная стоимость капитала",
                self.opportunity_cost_minor,
            ),
        ];
        for (name, value) in values {
            if value < 0 {
                return Err(DiscoveryError::NegativeAmount(name));
            }
        }
        if self.capital_required_minor == 0 {
            return Err(DiscoveryError::ZeroCapitalRequired);
        }
        if self.probability_bps > 10_000 {
            return Err(DiscoveryError::InvalidProbability(self.probability_bps));
        }
        if self.period_days == 0 {
            return Err(DiscoveryError::ZeroPeriod);
        }
        Ok(())
    }
}

/// Категория результата расчёта ожидаемой прибыли.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfitClassification {
    PositiveExpectedProfit,
    BreakEven,
    NegativeExpectedProfit,
}

/// Результат расчёта. Это оценка гипотезы, а не реализованная прибыль.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfitResult {
    pub currency: CurrencyCode,
    pub base_net_profit_minor: i128,
    pub expected_net_profit_minor: i128,
    pub capital_required_minor: i128,
    /// Доходность на требуемый капитал в базисных пунктах за весь период.
    pub return_on_capital_bps: i128,
    pub period_days: u32,
    pub classification: ProfitClassification,
}

/// Гипотеза об экономической возможности.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpportunityHypothesis {
    pub id: String,
    pub title: String,
    pub description: String,
    pub node_ids: Vec<String>,
    pub relation_ids: Vec<String>,
    pub estimate: ProfitEstimate,
}

impl OpportunityHypothesis {
    pub fn validate_against(&self, map: &EconomicMap) -> Result<(), DiscoveryError> {
        if self.id.trim().is_empty() || self.title.trim().is_empty() {
            return Err(DiscoveryError::EmptyIdentifierOrLabel);
        }
        if self.node_ids.is_empty() || self.relation_ids.is_empty() {
            return Err(DiscoveryError::EmptyHypothesisStructure);
        }

        let nodes: BTreeSet<&str> = self.node_ids.iter().map(String::as_str).collect();
        if nodes.len() != self.node_ids.len() {
            return Err(DiscoveryError::DuplicateHypothesisReference);
        }
        let relations: BTreeSet<&str> = self.relation_ids.iter().map(String::as_str).collect();
        if relations.len() != self.relation_ids.len() {
            return Err(DiscoveryError::DuplicateHypothesisReference);
        }

        for node_id in &self.node_ids {
            if map.node(node_id).is_none() {
                return Err(DiscoveryError::MissingNode(node_id.clone()));
            }
        }
        for relation_id in &self.relation_ids {
            let relation = map
                .relation(relation_id)
                .ok_or_else(|| DiscoveryError::MissingRelation(relation_id.clone()))?;
            if !nodes.contains(relation.from.as_str()) || !nodes.contains(relation.to.as_str()) {
                return Err(DiscoveryError::RelationOutsideHypothesis(
                    relation_id.clone(),
                ));
            }
        }
        self.estimate.validate()
    }
}

/// Возможность с рассчитанной экономикой.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatedOpportunity {
    pub id: String,
    pub title: String,
    pub result: ProfitResult,
}

/// Минимальный детерминированный механизм проверки и ранжирования гипотез.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscoveryEngine;

impl DiscoveryEngine {
    pub fn evaluate(
        &self,
        map: &EconomicMap,
        hypothesis: &OpportunityHypothesis,
    ) -> Result<ProfitResult, DiscoveryError> {
        hypothesis.validate_against(map)?;
        let estimate = &hypothesis.estimate;

        let base_net = estimate
            .gross_revenue_minor
            .checked_sub(estimate.direct_costs_minor)
            .and_then(|value| value.checked_sub(estimate.operating_costs_minor))
            .and_then(|value| value.checked_sub(estimate.financing_costs_minor))
            .and_then(|value| value.checked_sub(estimate.tax_costs_minor))
            .ok_or(DiscoveryError::ArithmeticOverflow)?;

        let probability = i128::from(estimate.probability_bps);
        let failure_probability = 10_000_i128 - probability;
        let weighted_base = base_net
            .checked_mul(probability)
            .ok_or(DiscoveryError::ArithmeticOverflow)?;
        let weighted_downside = estimate
            .downside_loss_minor
            .checked_mul(failure_probability)
            .ok_or(DiscoveryError::ArithmeticOverflow)?;
        let expected_before_opportunity_cost = weighted_base
            .checked_sub(weighted_downside)
            .ok_or(DiscoveryError::ArithmeticOverflow)?
            / 10_000;
        let expected_net = expected_before_opportunity_cost
            .checked_sub(estimate.opportunity_cost_minor)
            .ok_or(DiscoveryError::ArithmeticOverflow)?;
        let return_on_capital = expected_net
            .checked_mul(10_000)
            .ok_or(DiscoveryError::ArithmeticOverflow)?
            / estimate.capital_required_minor;

        let classification = match expected_net.cmp(&0) {
            std::cmp::Ordering::Greater => ProfitClassification::PositiveExpectedProfit,
            std::cmp::Ordering::Equal => ProfitClassification::BreakEven,
            std::cmp::Ordering::Less => ProfitClassification::NegativeExpectedProfit,
        };

        Ok(ProfitResult {
            currency: estimate.currency.clone(),
            base_net_profit_minor: base_net,
            expected_net_profit_minor: expected_net,
            capital_required_minor: estimate.capital_required_minor,
            return_on_capital_bps: return_on_capital,
            period_days: estimate.period_days,
            classification,
        })
    }

    /// Ранжирует гипотезы отдельно по каждой валюте.
    ///
    /// Сравнение сумм в разных валютах без курса запрещено. Внутри валюты
    /// порядок: ожидаемая чистая прибыль по убыванию, капитал по возрастанию,
    /// затем идентификатор для стабильного результата.
    pub fn rank_by_currency(
        &self,
        map: &EconomicMap,
        hypotheses: &[OpportunityHypothesis],
    ) -> Result<BTreeMap<CurrencyCode, Vec<EvaluatedOpportunity>>, DiscoveryError> {
        let mut grouped: BTreeMap<CurrencyCode, Vec<EvaluatedOpportunity>> = BTreeMap::new();
        for hypothesis in hypotheses {
            let result = self.evaluate(map, hypothesis)?;
            grouped
                .entry(result.currency.clone())
                .or_default()
                .push(EvaluatedOpportunity {
                    id: hypothesis.id.clone(),
                    title: hypothesis.title.clone(),
                    result,
                });
        }

        for opportunities in grouped.values_mut() {
            opportunities.sort_by(|left, right| {
                right
                    .result
                    .expected_net_profit_minor
                    .cmp(&left.result.expected_net_profit_minor)
                    .then_with(|| {
                        left.result
                            .capital_required_minor
                            .cmp(&right.result.capital_required_minor)
                    })
                    .then_with(|| left.id.cmp(&right.id))
            });
        }
        Ok(grouped)
    }
}

/// Ошибки проверки экономической модели.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    EmptyIdentifierOrLabel,
    EmptyHypothesisStructure,
    DuplicateNode(String),
    DuplicateRelation(String),
    MissingNode(String),
    MissingRelation(String),
    SelfRelation(String),
    RelationOutsideHypothesis(String),
    DuplicateHypothesisReference,
    InvalidCurrencyCode(String),
    NegativeAmount(&'static str),
    ZeroCapitalRequired,
    InvalidProbability(u16),
    ZeroPeriod,
    ArithmeticOverflow,
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifierOrLabel => write!(formatter, "пустой идентификатор или название"),
            Self::EmptyHypothesisStructure => {
                write!(formatter, "гипотеза не содержит объектов или отношений")
            }
            Self::DuplicateNode(id) => write!(formatter, "повторный экономический объект: {id}"),
            Self::DuplicateRelation(id) => write!(formatter, "повторное отношение: {id}"),
            Self::MissingNode(id) => write!(formatter, "экономический объект не найден: {id}"),
            Self::MissingRelation(id) => {
                write!(formatter, "экономическое отношение не найдено: {id}")
            }
            Self::SelfRelation(id) => {
                write!(formatter, "самоссылочное отношение не допускается: {id}")
            }
            Self::RelationOutsideHypothesis(id) => {
                write!(formatter, "отношение выходит за границы гипотезы: {id}")
            }
            Self::DuplicateHypothesisReference => {
                write!(formatter, "повторная ссылка внутри гипотезы")
            }
            Self::InvalidCurrencyCode(code) => write!(formatter, "некорректный код валюты: {code}"),
            Self::NegativeAmount(name) => write!(formatter, "отрицательное значение поля: {name}"),
            Self::ZeroCapitalRequired => {
                write!(formatter, "требуемый капитал должен быть больше нуля")
            }
            Self::InvalidProbability(value) => {
                write!(formatter, "вероятность вне диапазона 0..=10000: {value}")
            }
            Self::ZeroPeriod => write!(formatter, "период должен быть больше нуля"),
            Self::ArithmeticOverflow => write!(formatter, "переполнение при расчёте прибыли"),
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_map() -> EconomicMap {
        let mut map = EconomicMap::new();
        map.add_node(EconomicNode::new("bank", "Банковский счёт", ValueForm::BankDeposit).unwrap())
            .unwrap();
        map.add_node(EconomicNode::new("stablecoin", "Стейблкоин", ValueForm::Stablecoin).unwrap())
            .unwrap();
        map.add_node(
            EconomicNode::new(
                "settlement",
                "Международный расчёт",
                ValueForm::Other("расчётная операция".into()),
            )
            .unwrap(),
        )
        .unwrap();
        map.add_relation(
            EconomicRelation::new("r1", "bank", "stablecoin", RelationKind::ConvertsInto, None)
                .unwrap(),
        )
        .unwrap();
        map.add_relation(
            EconomicRelation::new(
                "r2",
                "stablecoin",
                "settlement",
                RelationKind::Enables,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        map
    }

    fn sample_hypothesis(id: &str, revenue: i128) -> OpportunityHypothesis {
        OpportunityHypothesis {
            id: id.into(),
            title: format!("Гипотеза {id}"),
            description: "Синтетический тестовый пример, не рыночный прогноз.".into(),
            node_ids: vec!["bank".into(), "stablecoin".into(), "settlement".into()],
            relation_ids: vec!["r1".into(), "r2".into()],
            estimate: ProfitEstimate {
                currency: CurrencyCode::new("USD").unwrap(),
                gross_revenue_minor: revenue,
                direct_costs_minor: 100_000,
                operating_costs_minor: 100_000,
                financing_costs_minor: 50_000,
                tax_costs_minor: 50_000,
                downside_loss_minor: 200_000,
                probability_bps: 8_000,
                capital_required_minor: 500_000,
                opportunity_cost_minor: 10_000,
                period_days: 30,
            },
        }
    }

    #[test]
    fn discovers_two_step_structural_candidate() {
        let map = sample_map();
        let candidates = map.two_step_candidates();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].node_ids,
            vec![
                "bank".to_string(),
                "stablecoin".to_string(),
                "settlement".to_string()
            ]
        );
        assert_eq!(
            candidates[0].relation_ids,
            vec!["r1".to_string(), "r2".to_string()]
        );
    }

    #[test]
    fn computes_probability_weighted_net_profit() {
        let map = sample_map();
        let result = DiscoveryEngine
            .evaluate(&map, &sample_hypothesis("h1", 1_000_000))
            .unwrap();
        assert_eq!(result.base_net_profit_minor, 700_000);
        assert_eq!(result.expected_net_profit_minor, 510_000);
        assert_eq!(result.return_on_capital_bps, 10_200);
        assert_eq!(
            result.classification,
            ProfitClassification::PositiveExpectedProfit
        );
    }

    #[test]
    fn ranks_only_inside_the_same_currency() {
        let map = sample_map();
        let hypotheses = vec![
            sample_hypothesis("lower", 800_000),
            sample_hypothesis("higher", 1_000_000),
        ];
        let ranked = DiscoveryEngine.rank_by_currency(&map, &hypotheses).unwrap();
        let usd = ranked.get(&CurrencyCode::new("USD").unwrap()).unwrap();
        assert_eq!(usd[0].id, "higher");
        assert_eq!(usd[1].id, "lower");
    }

    #[test]
    fn keeps_different_currencies_in_separate_groups() {
        let map = sample_map();
        let usd = sample_hypothesis("usd", 1_000_000);
        let mut eur = sample_hypothesis("eur", 1_000_000);
        eur.estimate.currency = CurrencyCode::new("EUR").unwrap();

        let ranked = DiscoveryEngine
            .rank_by_currency(&map, &[usd.clone(), eur])
            .unwrap();
        assert_eq!(ranked.len(), 2);
        assert_eq!(
            ranked
                .get(&CurrencyCode::new("USD").unwrap())
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            ranked
                .get(&CurrencyCode::new("EUR").unwrap())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_missing_economic_objects() {
        let mut map = sample_map();
        let relation =
            EconomicRelation::new("r3", "unknown", "bank", RelationKind::Transfers, None).unwrap();
        assert_eq!(
            map.add_relation(relation),
            Err(DiscoveryError::MissingNode("unknown".into()))
        );
    }

    #[test]
    fn rejects_probability_above_one_hundred_percent() {
        let map = sample_map();
        let mut hypothesis = sample_hypothesis("invalid", 1_000_000);
        hypothesis.estimate.probability_bps = 10_001;
        assert_eq!(
            DiscoveryEngine.evaluate(&map, &hypothesis),
            Err(DiscoveryError::InvalidProbability(10_001))
        );
    }

    #[test]
    fn rejects_zero_required_capital() {
        let map = sample_map();
        let mut hypothesis = sample_hypothesis("invalid", 1_000_000);
        hypothesis.estimate.capital_required_minor = 0;
        assert_eq!(
            DiscoveryEngine.evaluate(&map, &hypothesis),
            Err(DiscoveryError::ZeroCapitalRequired)
        );
    }

    #[test]
    fn rejects_relation_outside_hypothesis() {
        let map = sample_map();
        let mut hypothesis = sample_hypothesis("invalid", 1_000_000);
        hypothesis.node_ids.pop();
        assert_eq!(
            DiscoveryEngine.evaluate(&map, &hypothesis),
            Err(DiscoveryError::RelationOutsideHypothesis("r2".into()))
        );
    }

    #[test]
    fn keeps_negative_expected_profit_visible() {
        let map = sample_map();
        let result = DiscoveryEngine
            .evaluate(&map, &sample_hypothesis("loss", 100_000))
            .unwrap();
        assert!(result.expected_net_profit_minor < 0);
        assert_eq!(
            result.classification,
            ProfitClassification::NegativeExpectedProfit
        );
    }

    #[test]
    fn currency_code_must_be_three_uppercase_letters() {
        assert!(CurrencyCode::new("USD").is_ok());
        assert!(CurrencyCode::new("usd").is_err());
        assert!(CurrencyCode::new("US").is_err());
    }
}
