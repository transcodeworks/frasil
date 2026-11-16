//! The settings and fixed values of deposit tokens (ext-deposit-tokens.md,
//! 2.6 Settings, and overview.md, 6.8 Every timer).
//!
//! | Setting | Scope | Default | Range | Set by |
//! |---|---|---|---|---|
//! | `deposit_allowance` | a library | the operator's default; 64 if it sets none | 0 to 65,536 tokens per window | the operator, or the issuer for its libraries |
//! | `space_share` | a library, for each of its spaces | 16 | 0 to `deposit_allowance` tokens per window | the same |
//! | `token_period` | the peer | 7 days | 1 to 30 days | the operator |
//! | token budget | the peer | the operator's | items and bytes, apart from the anonymous budget | the operator |

const HOUR: u64 = 3_600;
const DAY: u64 = 24 * HOUR;

/// `token_period` by default: 7 days.
pub const TOKEN_PERIOD: u64 = 7 * DAY;

/// The range of `token_period`: 1 to 30 days.
pub const TOKEN_PERIOD_RANGE: (u64, u64) = (DAY, 30 * DAY);

/// `allowance_window`: a library's allowance counts the tokens drawn in 24
/// hours from the window's first draw, on the lower estimate of the
/// library's timeline.
pub const ALLOWANCE_WINDOW: u64 = DAY;

/// `deposit_allowance` where the operator sets no default: 64 tokens per
/// window.
pub const DEPOSIT_ALLOWANCE: u64 = 64;

/// The range of `deposit_allowance`: 0 to 65,536 tokens per window.
pub const DEPOSIT_ALLOWANCE_RANGE: (u64, u64) = (0, 65_536);

/// `space_share` by default: 16 tokens per window. Its range is 0 to the
/// library's `deposit_allowance`.
pub const SPACE_SHARE: u64 = 16;

/// A device's key consistency rule: three issuing keys of one peer whose
/// first sights lie less than this apart are `KeyInconsistent`
/// (ext-deposit-tokens.md, 3.2 Learning a peer's keys).
pub const CONSISTENCY_WINDOW: u64 = DAY;

/// The low mark below which a device draws a batch, by default
/// (ext-deposit-tokens.md, 3.12 When to draw, and how many).
pub const LOW_MARK: usize = 4;

/// A batch's size, by default.
pub const BATCH: usize = 16;

/// A library's allowance settings. A library the peer does not know yet
/// has the defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DepositSettings {
    /// `deposit_allowance`: the tokens the library draws per window.
    pub deposit_allowance: u64,
    /// `space_share`: the tokens each of its spaces' writers draw per
    /// window by space draws.
    pub space_share: u64,
}

impl Default for DepositSettings {
    fn default() -> Self {
        Self {
            deposit_allowance: DEPOSIT_ALLOWANCE,
            space_share: SPACE_SHARE,
        }
    }
}

impl DepositSettings {
    /// Whether the settings are in their ranges: an allowance of at most
    /// 65,536, and a share of at most the allowance.
    pub fn is_valid(&self) -> bool {
        self.deposit_allowance <= DEPOSIT_ALLOWANCE_RANGE.1
            && self.space_share <= self.deposit_allowance
    }
}
