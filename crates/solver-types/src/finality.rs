use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFinalityMode {
	Numeric,
	Safe,
	Finalized,
	Conservative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFinalityRule {
	pub mode: SourceFinalityMode,
	pub blocks: u64,
	pub block_time_seconds: u64,
	pub expected_delay_seconds: Option<u64>,
}

/// Select the source-chain head that is safe to consume.
///
/// The configured numeric depth is always enforced. Finalized/safe tags may
/// make the result more conservative, but never newer than `latest - depth`.
pub fn select_finality_head(
	finalized: Option<u64>,
	safe: Option<u64>,
	latest: u64,
	finality_blocks: u64,
) -> Option<u64> {
	let numeric = latest.checked_sub(finality_blocks)?;
	let mut head = numeric;

	for tagged in [finalized, safe]
		.into_iter()
		.flatten()
		.filter(|block| *block > 0)
	{
		head = head.min(tagged);
	}

	Some(head)
}

pub fn select_source_finality_head(
	finalized: Option<u64>,
	safe: Option<u64>,
	latest: u64,
	rule: SourceFinalityRule,
) -> Option<u64> {
	let numeric = latest.checked_sub(rule.blocks)?;
	match rule.mode {
		SourceFinalityMode::Numeric => Some(numeric),
		SourceFinalityMode::Safe => non_genesis_tag(safe).map(|tag| numeric.min(tag)),
		SourceFinalityMode::Finalized => non_genesis_tag(finalized).map(|tag| numeric.min(tag)),
		SourceFinalityMode::Conservative => Some(conservative_head(finalized, safe, numeric)),
	}
}

fn conservative_head(finalized: Option<u64>, safe: Option<u64>, numeric: u64) -> u64 {
	let mut head = numeric;
	for tagged in [finalized, safe].into_iter().filter_map(non_genesis_tag) {
		head = head.min(tagged);
	}
	head
}

fn non_genesis_tag(tag: Option<u64>) -> Option<u64> {
	tag.filter(|block| *block > 0)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn finality_head_enforces_numeric_depth_when_tags_track_latest() {
		assert_eq!(
			select_finality_head(Some(100), Some(100), 100, 20),
			Some(80)
		);
	}

	#[test]
	fn finality_head_uses_older_finalized_tag_when_more_conservative() {
		assert_eq!(select_finality_head(Some(70), Some(90), 100, 20), Some(70));
	}

	#[test]
	fn finality_head_returns_none_before_numeric_depth_elapses() {
		assert_eq!(select_finality_head(Some(5), Some(5), 10, 20), None);
	}

	#[test]
	fn finality_head_ignores_genesis_tags() {
		assert_eq!(select_finality_head(Some(0), Some(0), 100, 20), Some(80));
	}

	fn rule(mode: SourceFinalityMode, blocks: u64) -> SourceFinalityRule {
		SourceFinalityRule {
			mode,
			blocks,
			block_time_seconds: 12,
			expected_delay_seconds: None,
		}
	}

	#[test]
	fn source_finality_numeric_uses_numeric_depth_only() {
		assert_eq!(
			select_source_finality_head(
				Some(70),
				Some(75),
				100,
				rule(SourceFinalityMode::Numeric, 20),
			),
			Some(80)
		);
	}

	#[test]
	fn source_finality_safe_uses_safe_tag_when_present() {
		assert_eq!(
			select_source_finality_head(
				Some(70),
				Some(75),
				100,
				rule(SourceFinalityMode::Safe, 20),
			),
			Some(75)
		);
	}

	#[test]
	fn source_finality_safe_requires_non_genesis_safe_tag() {
		assert_eq!(
			select_source_finality_head(None, None, 100, rule(SourceFinalityMode::Safe, 20)),
			None
		);
		assert_eq!(
			select_source_finality_head(Some(70), Some(0), 100, rule(SourceFinalityMode::Safe, 20)),
			None
		);
	}

	#[test]
	fn source_finality_finalized_uses_finalized_tag_when_present() {
		assert_eq!(
			select_source_finality_head(
				Some(70),
				Some(75),
				100,
				rule(SourceFinalityMode::Finalized, 20),
			),
			Some(70)
		);
	}

	#[test]
	fn source_finality_finalized_requires_non_genesis_finalized_tag() {
		assert_eq!(
			select_source_finality_head(
				None,
				Some(80),
				100,
				rule(SourceFinalityMode::Finalized, 20)
			),
			None
		);
		assert_eq!(
			select_source_finality_head(
				Some(0),
				Some(80),
				100,
				rule(SourceFinalityMode::Finalized, 20)
			),
			None
		);
	}

	#[test]
	fn source_finality_conservative_preserves_existing_behavior() {
		assert_eq!(
			select_source_finality_head(
				Some(70),
				Some(90),
				100,
				rule(SourceFinalityMode::Conservative, 20),
			),
			Some(70)
		);
		assert_eq!(
			select_source_finality_head(
				Some(0),
				Some(0),
				100,
				rule(SourceFinalityMode::Conservative, 20),
			),
			Some(80)
		);
	}
}
