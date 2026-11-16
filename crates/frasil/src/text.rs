//! Comparing two versions of a document's text, as a list of splices, away
//! from the engine, and folding a text's line endings and byte order mark
//! for that comparison.
//!
//! The comparison goes from coarse to fine. It trims what both versions
//! start and end with, aligns whole lines, then the words of each changed
//! run of lines, then the characters of a small changed region, so a save
//! costs what it changed and an edit within a line still merges with
//! another. Every level is bounded: a pair of runs too far apart to align
//! is treated as changed whole, which is coarser and never wrong.

use std::collections::HashMap;
use std::time::Duration;

/// The most edits the alignment of one pair of runs looks for. It costs
/// about the square of this in time and in memory.
const MOST_EDITS: usize = 2048;
/// The longest run, in characters, compared character by character.
const MOST_REFINED: usize = 256;
/// The part of a changed run, of 100, that must stay for it to be edited
/// rather than replaced: below it, what matched is chance, and an edit made
/// of its fragments would interleave with another writer's.
const LEAST_KEPT: usize = 50;
/// The most splices times the text's length: importing a change takes
/// about 0.7 ns for each pair of an operation and a character of the
/// document, at every replica and under its engine.
const MOST_WORK: usize = 1 << 30;
/// The fewest splices a text may keep, however long it is.
const LEAST_SPLICES: usize = 64;
/// How deep patience alignment divides a pair of runs.
const MOST_DEPTH: usize = 32;
/// How far the alignment goes between readings of the clock.
const CHECK_EVERY: u64 = 1 << 16;
/// How much alignment a millisecond buys where there is no clock to read.
#[cfg(target_arch = "wasm32")]
const STEPS_PER_MS: u64 = 100_000;

/// One change to a text: at character `at` of the text it was compared
/// against, `delete` characters give way to `insert`. Splices of one
/// comparison are in order, and do not overlap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSplice {
    /// Where, in Unicode code points.
    pub at: usize,
    /// How many code points go.
    pub delete: usize,
    /// What comes in their place.
    pub insert: String,
}

/// What [`compare_text`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// The changes, in order. Empty when the texts are the same.
    pub splices: Vec<TextSplice>,
    /// Whether most of the text changed, or the limit passed, so that the
    /// changed part is replaced in one operation.
    pub replaced: bool,
    /// Whether the limit passed.
    pub limit_passed: bool,
}

/// The time limit passed before the comparison finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped;

/// What a comparison may spend.
struct Limit {
    #[cfg(not(target_arch = "wasm32"))]
    deadline: Option<std::time::Instant>,
    #[cfg(target_arch = "wasm32")]
    allowance: u64,
    spent: u64,
    check_at: u64,
}

impl Limit {
    fn new(limit: Duration) -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            deadline: std::time::Instant::now().checked_add(limit),
            // `Instant` has no clock behind it in a browser.
            #[cfg(target_arch = "wasm32")]
            allowance: u64::try_from(limit.as_millis())
                .unwrap_or(u64::MAX)
                .saturating_mul(STEPS_PER_MS),
            spent: 0,
            check_at: 0,
        }
    }

    fn spend(&mut self, steps: usize) -> Result<(), Stopped> {
        self.spent = self.spent.saturating_add(steps as u64);
        if self.spent < self.check_at {
            return Ok(());
        }
        self.check_at = self.spent.saturating_add(CHECK_EVERY);
        #[cfg(not(target_arch = "wasm32"))]
        let over = self
            .deadline
            .is_some_and(|deadline| std::time::Instant::now() >= deadline);
        #[cfg(target_arch = "wasm32")]
        let over = self.spent >= self.allowance;
        if over { Err(Stopped) } else { Ok(()) }
    }
}

/// A stretch both sides of an alignment share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Match {
    old: usize,
    new: usize,
    len: usize,
}

fn common_prefix<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn common_suffix<T: PartialEq>(a: &[T], b: &[T]) -> usize {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .take_while(|(x, y)| x == y)
        .count()
}

/// The stretches `old` and `new` share, in order: patience alignment
/// (lines found once on each side anchor the rest), then Myers' greedy
/// algorithm where no anchor is left.
fn align(
    old: &[u32],
    new: &[u32],
    depth: usize,
    limit: &mut Limit,
    out: &mut Vec<Match>,
    at: (usize, usize),
) -> Result<(), Stopped> {
    let head = common_prefix(old, new);
    if head > 0 {
        out.push(Match {
            old: at.0,
            new: at.1,
            len: head,
        });
    }
    let (old, new) = (&old[head..], &new[head..]);
    let tail = common_suffix(old, new);
    let (end_old, end_new) = (old.len() - tail, new.len() - tail);
    let (mid_old, mid_new) = (&old[..end_old], &new[..end_new]);
    let base = (at.0 + head, at.1 + head);
    limit.spend(mid_old.len() + mid_new.len())?;
    if !mid_old.is_empty() && !mid_new.is_empty() {
        let anchors = if depth < MOST_DEPTH {
            anchors(mid_old, mid_new)
        } else {
            Vec::new()
        };
        if anchors.is_empty() {
            myers(mid_old, mid_new, limit, out, base)?;
        } else {
            let (mut from_old, mut from_new) = (0, 0);
            for (to_old, to_new) in anchors {
                align(
                    &mid_old[from_old..to_old],
                    &mid_new[from_new..to_new],
                    depth + 1,
                    limit,
                    out,
                    (base.0 + from_old, base.1 + from_new),
                )?;
                out.push(Match {
                    old: base.0 + to_old,
                    new: base.1 + to_new,
                    len: 1,
                });
                (from_old, from_new) = (to_old + 1, to_new + 1);
            }
            align(
                &mid_old[from_old..],
                &mid_new[from_new..],
                depth + 1,
                limit,
                out,
                (base.0 + from_old, base.1 + from_new),
            )?;
        }
    }
    if tail > 0 {
        out.push(Match {
            old: base.0 + end_old,
            new: base.1 + end_new,
            len: tail,
        });
    }
    Ok(())
}

/// The tokens found exactly once on each side, as far as they keep their
/// order: the longest increasing run of their places.
fn anchors(old: &[u32], new: &[u32]) -> Vec<(usize, usize)> {
    let mut seen: HashMap<u32, (u32, u32, usize, usize)> = HashMap::new();
    for (place, token) in old.iter().enumerate() {
        let entry = seen.entry(*token).or_default();
        entry.0 += 1;
        entry.2 = place;
    }
    for (place, token) in new.iter().enumerate() {
        if let Some(entry) = seen.get_mut(token) {
            entry.1 += 1;
            entry.3 = place;
        }
    }
    let mut unique: Vec<(usize, usize)> = seen
        .into_values()
        .filter(|entry| entry.0 == 1 && entry.1 == 1)
        .map(|entry| (entry.2, entry.3))
        .collect();
    unique.sort_unstable();

    // Patience sorting: `piles[i]` ends the best run of length `i + 1`.
    let mut piles: Vec<usize> = Vec::new();
    let mut before: Vec<Option<usize>> = vec![None; unique.len()];
    for index in 0..unique.len() {
        let pile = piles.partition_point(|&top| unique[top].1 < unique[index].1);
        if pile > 0 {
            before[index] = Some(piles[pile - 1]);
        }
        if pile == piles.len() {
            piles.push(index);
        } else {
            piles[pile] = index;
        }
    }
    let mut run = Vec::with_capacity(piles.len());
    let mut at = piles.last().copied();
    while let Some(index) = at {
        run.push(unique[index]);
        at = before[index];
    }
    run.reverse();
    run
}

/// Myers' greedy shortest edit script, given up past [`MOST_EDITS`]: the
/// runs then share nothing, as far as this says.
fn myers(
    old: &[u32],
    new: &[u32],
    limit: &mut Limit,
    out: &mut Vec<Match>,
    at: (usize, usize),
) -> Result<(), Stopped> {
    let (n, m) = (old.len() as isize, new.len() as isize);
    let most = MOST_EDITS.min(old.len() + new.len()) as isize;
    let offset = most + 1;
    let mut furthest = vec![0isize; 2 * most as usize + 3];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let get = |row: &[isize], d: isize, k: isize| row[(k + d) as usize];
    let mut reached = None;
    'edits: for d in 0..=most {
        limit.spend(d as usize + 1)?;
        trace.push(furthest[(offset - d) as usize..=(offset + d) as usize].to_vec());
        for k in (-d..=d).step_by(2) {
            let down = k == -d
                || (k != d
                    && furthest[(offset + k - 1) as usize] < furthest[(offset + k + 1) as usize]);
            let mut x = if down {
                furthest[(offset + k + 1) as usize]
            } else {
                furthest[(offset + k - 1) as usize] + 1
            };
            let mut y = x - k;
            let from = x;
            while x < n && y < m && old[x as usize] == new[y as usize] {
                x += 1;
                y += 1;
            }
            limit.spend((x - from) as usize)?;
            furthest[(offset + k) as usize] = x;
            if x == n && y == m {
                reached = Some(d);
                break 'edits;
            }
        }
    }
    let Some(edits) = reached else {
        return Ok(());
    };
    let (mut x, mut y) = (n, m);
    let start = out.len();
    for d in (1..=edits).rev() {
        let row = &trace[d as usize];
        let k = x - y;
        let down = k == -d || (k != d && get(row, d, k - 1) < get(row, d, k + 1));
        let previous_k = if down { k + 1 } else { k - 1 };
        let previous_x = get(row, d, previous_k);
        let previous_y = previous_x - previous_k;
        let (step_x, step_y) = if down {
            (previous_x, previous_y + 1)
        } else {
            (previous_x + 1, previous_y)
        };
        if x > step_x {
            out.push(Match {
                old: at.0 + step_x as usize,
                new: at.1 + step_y as usize,
                len: (x - step_x) as usize,
            });
        }
        (x, y) = (previous_x, previous_y);
    }
    if x > 0 {
        out.push(Match {
            old: at.0,
            new: at.1,
            len: x as usize,
        });
    }
    out[start..].reverse();
    Ok(())
}

/// Interns slices as numbers, so tokens compare in one step.
#[derive(Default)]
struct Interner<'a> {
    ids: HashMap<&'a [char], u32>,
}

impl<'a> Interner<'a> {
    fn id(&mut self, token: &'a [char]) -> u32 {
        let next = self.ids.len() as u32;
        *self.ids.entry(token).or_insert(next)
    }
}

/// The lines of `text`, as `(start, end)` from `base`: a line keeps its
/// `\n`.
fn line_spans(text: &[char], base: usize) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (place, c) in text.iter().enumerate() {
        if *c == '\n' {
            spans.push((base + start, base + place + 1));
            start = place + 1;
        }
    }
    if start < text.len() {
        spans.push((base + start, base + text.len()));
    }
    spans
}

/// The runs of non-space characters of `text`, as `(start, end)`.
fn word_spans(text: &[char]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = None;
    for (place, c) in text.iter().enumerate() {
        match (start, c.is_whitespace()) {
            (None, false) => start = Some(place),
            (Some(from), true) => {
                spans.push((from, place));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        spans.push((from, text.len()));
    }
    spans
}

/// The two texts, as characters, and the splices so far.
struct Comparing<'t> {
    old: &'t [char],
    new: &'t [char],
    splices: Vec<TextSplice>,
}

impl Comparing<'_> {
    fn splice(&mut self, old: (usize, usize), new: (usize, usize)) {
        if old.0 == old.1 && new.0 == new.1 {
            return;
        }
        self.splices.push(TextSplice {
            at: old.0,
            delete: old.1 - old.0,
            insert: self.new[new.0..new.1].iter().collect(),
        });
    }

    /// Replaces a run whole, but for what both sides of it start and end
    /// with: an indented line keeps its indent and its `\n`, so another
    /// writer's insert at either end stays in place.
    fn replace(&mut self, old: (usize, usize), new: (usize, usize)) {
        let head = common_prefix(&self.old[old.0..old.1], &self.new[new.0..new.1]);
        let (old, new) = ((old.0 + head, old.1), (new.0 + head, new.1));
        let tail = common_suffix(&self.old[old.0..old.1], &self.new[new.0..new.1]);
        self.splice((old.0, old.1 - tail), (new.0, new.1 - tail));
    }

    /// Lines: what they leave out goes to [`words`](Self::words).
    fn lines(
        &mut self,
        old: (usize, usize),
        new: (usize, usize),
        limit: &mut Limit,
    ) -> Result<(), Stopped> {
        let (old_text, new_text) = (self.old, self.new);
        let old_lines = line_spans(&old_text[old.0..old.1], old.0);
        let new_lines = line_spans(&new_text[new.0..new.1], new.0);
        let mut interner = Interner::default();
        let old_ids: Vec<u32> = old_lines
            .iter()
            .map(|(from, to)| interner.id(&old_text[*from..*to]))
            .collect();
        let new_ids: Vec<u32> = new_lines
            .iter()
            .map(|(from, to)| interner.id(&new_text[*from..*to]))
            .collect();
        let mut matches = Vec::new();
        align(&old_ids, &new_ids, 0, limit, &mut matches, (0, 0))?;
        let edge = |lines: &[(usize, usize)], place: usize, end: usize| {
            lines.get(place).map_or(end, |line| line.0)
        };
        let (mut from_old, mut from_new) = (0, 0);
        for found in matches {
            self.words(
                (
                    edge(&old_lines, from_old, old.1),
                    edge(&old_lines, found.old, old.1),
                ),
                (
                    edge(&new_lines, from_new, new.1),
                    edge(&new_lines, found.new, new.1),
                ),
                limit,
            )?;
            from_old = found.old + found.len;
            from_new = found.new + found.len;
        }
        self.words(
            (edge(&old_lines, from_old, old.1), old.1),
            (edge(&new_lines, from_new, new.1), new.1),
            limit,
        )
    }

    /// Words of a changed run of lines: when too little stays, the run is
    /// replaced; what they leave out goes to [`chars`](Self::chars).
    fn words(
        &mut self,
        old: (usize, usize),
        new: (usize, usize),
        limit: &mut Limit,
    ) -> Result<(), Stopped> {
        if old.0 == old.1 || new.0 == new.1 {
            self.splice(old, new);
            return Ok(());
        }
        let (old_text, new_text) = (self.old, self.new);
        let old_words = word_spans(&old_text[old.0..old.1]);
        let new_words = word_spans(&new_text[new.0..new.1]);
        let mut interner = Interner::default();
        let old_ids: Vec<u32> = old_words
            .iter()
            .map(|(from, to)| interner.id(&old_text[old.0 + from..old.0 + to]))
            .collect();
        let new_ids: Vec<u32> = new_words
            .iter()
            .map(|(from, to)| interner.id(&new_text[new.0 + from..new.0 + to]))
            .collect();
        let mut matches = Vec::new();
        align(&old_ids, &new_ids, 0, limit, &mut matches, (0, 0))?;
        let kept: usize = matches
            .iter()
            .flat_map(|found| found.old..found.old + found.len)
            .map(|place| old_words[place].1 - old_words[place].0)
            .sum();
        // Words against words: whitespace never counts as kept, so it does
        // not count towards what must stay either.
        let in_words =
            |words: &[(usize, usize)]| -> usize { words.iter().map(|(from, to)| to - from).sum() };
        let longest = in_words(&old_words).max(in_words(&new_words));
        if kept * 100 < longest * LEAST_KEPT {
            self.replace(old, new);
            return Ok(());
        }
        let (mut from_old, mut from_new) = (old.0, new.0);
        for found in matches {
            for place in 0..found.len {
                let word_old = old_words[found.old + place];
                let word_new = new_words[found.new + place];
                self.chars(
                    (from_old, old.0 + word_old.0),
                    (from_new, new.0 + word_new.0),
                    limit,
                )?;
                from_old = old.0 + word_old.1;
                from_new = new.0 + word_new.1;
            }
        }
        self.chars((from_old, old.1), (from_new, new.1), limit)
    }

    /// Characters of a small region: larger ones change whole.
    fn chars(
        &mut self,
        old: (usize, usize),
        new: (usize, usize),
        limit: &mut Limit,
    ) -> Result<(), Stopped> {
        let head = common_prefix(&self.old[old.0..old.1], &self.new[new.0..new.1]);
        let (old, new) = ((old.0 + head, old.1), (new.0 + head, new.1));
        let tail = common_suffix(&self.old[old.0..old.1], &self.new[new.0..new.1]);
        let (old, new) = ((old.0, old.1 - tail), (new.0, new.1 - tail));
        let (old_len, new_len) = (old.1 - old.0, new.1 - new.0);
        if old_len == 0 || new_len == 0 || old_len.max(new_len) > MOST_REFINED {
            self.splice(old, new);
            return Ok(());
        }
        let code = |c: &char| *c as u32;
        let old_codes: Vec<u32> = self.old[old.0..old.1].iter().map(code).collect();
        let new_codes: Vec<u32> = self.new[new.0..new.1].iter().map(code).collect();
        let mut matches = Vec::new();
        align(
            &old_codes,
            &new_codes,
            0,
            limit,
            &mut matches,
            (old.0, new.0),
        )?;
        let kept: usize = matches.iter().map(|found| found.len).sum();
        if kept * 100 < old_len.max(new_len) * LEAST_KEPT {
            self.splice(old, new);
            return Ok(());
        }
        let (mut from_old, mut from_new) = (old.0, new.0);
        for found in matches {
            self.splice((from_old, found.old), (from_new, found.new));
            from_old = found.old + found.len;
            from_new = found.new + found.len;
        }
        self.splice((from_old, old.1), (from_new, new.1));
        Ok(())
    }
}

/// Compares `new` with `old`, within `limit`.
///
/// When most of the text changed, the changed part is replaced in one
/// splice, between what both versions start and end with: a diff of two
/// unrelated texts finds chance matches, and its fragments would interleave
/// with another writer's.
///
/// # Errors
///
/// [`Stopped`] when `limit` passes.
pub fn compare_text(old: &str, new: &str, limit: Duration) -> Result<Comparison, Stopped> {
    if old == new {
        return Ok(Comparison {
            splices: Vec::new(),
            replaced: false,
            limit_passed: false,
        });
    }
    let old: Vec<char> = old.chars().collect();
    let new: Vec<char> = new.chars().collect();
    let head = common_prefix(&old, &new);
    let tail = common_suffix(&old[head..], &new[head..]);
    let changed_old = (head, old.len() - tail);
    let changed_new = (head, new.len() - tail);
    let mut comparing = Comparing {
        old: &old,
        new: &new,
        splices: Vec::new(),
    };
    let mut limit = Limit::new(limit);
    let whole = (changed_old, changed_new);
    if changed_old.0 == changed_old.1 || changed_new.0 == changed_new.1 {
        comparing.splice(changed_old, changed_new);
    } else {
        comparing.lines(changed_old, changed_new, &mut limit)?;
    }
    let touched: usize = comparing
        .splices
        .iter()
        .map(|splice| splice.delete.max(splice.insert.chars().count()))
        .sum();
    let longest = comparing.old.len().max(comparing.new.len());
    let replaced = touched * 100 > longest * (100 - LEAST_KEPT);
    if replaced && comparing.splices.len() > 1 {
        comparing.splices.clear();
        comparing.splice(whole.0, whole.1);
    }
    let splices = joined(comparing.splices, &old);
    Ok(Comparison {
        splices,
        replaced,
        limit_passed: false,
    })
}

/// Splices near each other joined, the text between them rewritten as it
/// was, until few enough are left for the document's length ([`MOST_WORK`]):
/// a change all over a long text then costs bytes, not minutes of every
/// replica's time.
fn joined(mut splices: Vec<TextSplice>, old: &[char]) -> Vec<TextSplice> {
    let allowed = (MOST_WORK / old.len().max(1)).max(LEAST_SPLICES);
    let mut gap = 8;
    while splices.len() > allowed {
        let mut kept: Vec<TextSplice> = Vec::with_capacity(splices.len() / 2);
        for splice in splices {
            match kept.last_mut() {
                Some(last) if splice.at - (last.at + last.delete) <= gap => {
                    let between = last.at + last.delete..splice.at;
                    last.delete = splice.at + splice.delete - last.at;
                    last.insert.extend(&old[between]);
                    last.insert.push_str(&splice.insert);
                }
                _ => kept.push(splice),
            }
        }
        splices = kept;
        gap *= 2;
    }
    splices
}

/// What the time limit leaves, with no comparison at all: the part of `old` between
/// what both versions start and end with gives way to the same part of
/// `new`, in one splice. Always within any limit.
pub fn replace_text(old: &str, new: &str) -> Comparison {
    let old: Vec<char> = old.chars().collect();
    let new: Vec<char> = new.chars().collect();
    let head = common_prefix(&old, &new);
    let tail = common_suffix(&old[head..], &new[head..]);
    let (old_end, new_end) = (old.len() - tail, new.len() - tail);
    let mut comparing = Comparing {
        old: &old,
        new: &new,
        splices: Vec::new(),
    };
    comparing.splice((head, old_end), (head, new_end));
    Comparison {
        splices: comparing.splices,
        replaced: true,
        limit_passed: true,
    }
}

/// Divides splices so that each division costs at most `budget` bytes, by
/// what it inserts and a fixed price per operation. An insertion larger
/// than `budget` is cut at a character boundary. The divisions apply one
/// after the other, and the places in each are in the text the last one
/// left.
pub(crate) fn divide(splices: Vec<TextSplice>, budget: usize) -> Vec<Vec<TextSplice>> {
    /// What an operation costs in Loro's encoding beyond its text: twice
    /// what a change of many small operations was measured to need.
    const OPERATION: usize = 16;
    let budget = budget.max(OPERATION + 4);
    let mut divisions: Vec<Vec<TextSplice>> = vec![Vec::new()];
    let mut used = 0;
    // How far what is written so far moved the text, and how far it had
    // when this division began.
    let mut moved: isize = 0;
    let mut opening: isize = 0;
    for splice in splices {
        let mut place = splice.at.saturating_add_signed(moved);
        let mut rest = splice.insert.as_str();
        let mut delete = splice.delete;
        loop {
            if used + OPERATION + rest.len().min(4) > budget {
                divisions.push(Vec::new());
                used = 0;
                opening = moved;
            }
            let room = budget - used - OPERATION;
            let mut cut = rest.len().min(room);
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            let (part, next) = rest.split_at(cut);
            let inserted = part.chars().count();
            used += OPERATION + part.len();
            if let Some(division) = divisions.last_mut() {
                division.push(TextSplice {
                    at: place.saturating_add_signed(opening - moved),
                    delete,
                    insert: part.to_owned(),
                });
            }
            moved += inserted as isize - delete as isize;
            place += inserted;
            delete = 0;
            rest = next;
            if rest.is_empty() {
                break;
            }
        }
    }
    divisions
}

/// The line ending a text uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LineEnding {
    /// `\n`.
    #[default]
    Lf,
    /// `\r\n`.
    CrLf,
}

/// What [`TextStyle::fold`] took out of a text, for a caller to keep beside
/// it and hand to [`TextStyle::restore`]: Frasil does not store it. A file
/// mirror keeps it in the entry's own metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TextStyle {
    /// Whether the text started with a byte order mark.
    pub bom: bool,
    /// The line ending of most of its lines.
    pub line_ending: LineEnding,
    /// Whether its lines end in both ways. [`TextStyle::restore`] then
    /// gives every line [`line_ending`](Self::line_ending), so it does not
    /// give back the same bytes.
    pub mixed: bool,
}

impl TextStyle {
    /// A text with its byte order mark taken off and `\r\n` folded to
    /// `\n`, and the style to restore it with. A text folded so compares
    /// equal to its own line-ending flip.
    ///
    /// Unicode form is left to the caller, who folds it first, and keeps
    /// what it needs to restore it: this crate carries no Unicode tables.
    pub fn fold(text: &str) -> (String, Self) {
        let (bom, body) = match text.strip_prefix('\u{feff}') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let crlf = body.matches("\r\n").count();
        let lf = body.matches('\n').count() - crlf;
        let style = Self {
            bom,
            line_ending: if crlf > lf {
                LineEnding::CrLf
            } else {
                LineEnding::Lf
            },
            mixed: crlf > 0 && lf > 0,
        };
        let folded = if crlf > 0 {
            body.replace("\r\n", "\n")
        } else {
            body.to_owned()
        };
        (folded, style)
    }

    /// `text`, as folded, in this style.
    pub fn restore(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len() + 3);
        if self.bom {
            out.push('\u{feff}');
        }
        match self.line_ending {
            LineEnding::Lf => out.push_str(text),
            LineEnding::CrLf => out.push_str(&text.replace('\n', "\r\n")),
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn apply(old: &str, splices: &[TextSplice]) -> String {
        let mut text: Vec<char> = old.chars().collect();
        let mut shift = 0isize;
        for splice in splices {
            let at = splice.at.saturating_add_signed(shift);
            let inserted: Vec<char> = splice.insert.chars().collect();
            shift += inserted.len() as isize - splice.delete as isize;
            text.splice(at..at + splice.delete, inserted);
        }
        text.into_iter().collect()
    }

    fn check(old: &str, new: &str) -> Comparison {
        let comparison = compare_text(old, new, MINUTE).unwrap();
        assert_eq!(apply(old, &comparison.splices), new, "{old:?} to {new:?}");
        let mut end = 0;
        for splice in &comparison.splices {
            assert!(splice.at >= end, "splices in order: {comparison:?}");
            end = splice.at + splice.delete;
        }
        comparison
    }

    #[test]
    fn same_text_needs_no_splice() {
        assert!(check("one\ntwo\n", "one\ntwo\n").splices.is_empty());
        assert!(check("", "").splices.is_empty());
    }

    #[test]
    fn a_word_in_a_line_is_a_small_splice() {
        let comparison = check(
            "Nothing to be done.\nWe wait here.\nHe will come.\n",
            "Nothing to be done.\nWe wait right here.\nHe will come.\n",
        );
        assert_eq!(comparison.splices.len(), 1);
        assert_eq!(comparison.splices[0].insert, "right ");
        assert_eq!(comparison.splices[0].delete, 0);
    }

    /// Three edits, so the line between the first and the last is aligned
    /// as a whole run of its own, indent and `\n` included.
    #[test]
    fn a_word_in_an_indented_line_is_a_small_splice() {
        let old =
            "fn first() {\n    let a = 1;\n    return x;\n}\nfn second() {\n    return z;\n}\n";
        let new = "fn one() {\n    let a = 1;\n    return y;\n}\nfn second() {\n    return w;\n}\n";
        let comparison = check(old, new);
        assert!(!comparison.replaced);
        let at = old.find("x;").unwrap();
        let line = comparison
            .splices
            .iter()
            .find(|splice| splice.at <= at && at < splice.at + splice.delete.max(1))
            .expect("a splice in the middle line");
        assert_eq!((line.at, line.delete, line.insert.as_str()), (at, 1, "y"));
        for splice in &comparison.splices {
            assert!(splice.delete <= 5, "a word at most: {splice:?}");
        }
    }

    #[test]
    fn mostly_whitespace_runs_converge() {
        let pairs = [
            ("a\n  \n\t\n    \nb\n", "c\n \n\n\t\t\n    \nd\n"),
            ("x\n        ;\n        \ny", "z\n        ,\n    \t\nw"),
            ("1\n \n \n \n2", "3\n\n\n\n\n4"),
            ("{\n\t\t}\n\t\t{\n}", "[\n\t}\n\t\t\t{\n]"),
            ("a  b   c\n    \n  d", "e  b c\n\n      \n  f"),
        ];
        for (old, new) in pairs {
            check(old, new);
            check(new, old);
        }
        let mut seed = 7u64;
        let mut draw = |bound: u64| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 33) % bound
        };
        let pieces = [" ", "  ", "\t", "\n", "    ", "\n\n", "a", ";"];
        for _ in 0..500 {
            let mut make = || {
                (0..draw(60))
                    .map(|_| pieces[draw(8) as usize])
                    .collect::<String>()
            };
            let (old, new) = (make(), make());
            check(&old, &new);
        }
    }

    #[test]
    fn a_reflow_moves_only_the_spaces() {
        let old = "alpha beta gamma\ndelta epsilon zeta\n";
        let new = "alpha beta\ngamma delta\nepsilon zeta\n";
        let comparison = check(old, new);
        assert!(!comparison.replaced);
        assert!(comparison.splices.iter().all(|s| s.delete <= 1));
        assert_eq!(comparison.splices.len(), 3);
    }

    #[test]
    fn unrelated_texts_are_replaced_in_one_splice() {
        let comparison = check(
            "the road goes on and on\nby the tree we wait\n",
            "a wholly different sentence\nnothing is shared here\n",
        );
        assert_eq!(comparison.splices.len(), 1);
    }

    #[test]
    fn edges_and_multibyte_text_stay_exact() {
        for (old, new) in [
            ("", "new"),
            ("old", ""),
            ("a", "a\n"),
            ("a\n", "a"),
            ("é\nè\n", "è\né\n"),
            ("🎭 acte\n", "🎭 scène\n"),
            ("x\r\ny\r\n", "x\ny\n"),
            ("\n\n\n", "\n"),
            ("same\nsame\nsame\n", "same\nother\nsame\nsame\n"),
        ] {
            check(old, new);
        }
    }

    #[test]
    fn generated_pairs_round_trip() {
        let mut seed = 1u64;
        let mut draw = |bound: u64| {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 33) % bound
        };
        let words = ["a", "b", "cc", "dé", "\n", " ", "\n\n", "e f"];
        for _ in 0..500 {
            let mut make = || {
                (0..draw(40))
                    .map(|_| words[draw(8) as usize])
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            let (old, new) = (make(), make());
            check(&old, &new);
        }
    }

    #[test]
    fn the_limit_stops_a_comparison() {
        let old = "alpha beta\ngamma delta\n".repeat(50);
        let new = "alpha gamma\nbeta delta\n".repeat(50);
        assert_eq!(compare_text(&old, &new, Duration::ZERO), Err(Stopped));
    }

    #[test]
    fn replacing_keeps_what_both_ends_share() {
        let replaced = replace_text("head old tail", "head new text tail");
        assert_eq!(
            apply("head old tail", &replaced.splices),
            "head new text tail"
        );
        assert_eq!(replaced.splices.len(), 1);
        assert_eq!(replaced.splices[0].at, 5);
    }

    #[test]
    fn splices_all_over_a_long_text_are_joined() {
        let old: Vec<char> = "ab".repeat(1 << 20).chars().collect();
        let many: Vec<TextSplice> = (0..old.len())
            .step_by(16)
            .map(|at| TextSplice {
                at,
                delete: 1,
                insert: "é".to_owned(),
            })
            .collect();
        let text: String = old.iter().collect();
        let whole = apply(&text, &many);
        let fewer = joined(many, &old);
        assert!(fewer.len() * old.len() <= MOST_WORK);
        assert_eq!(apply(&text, &fewer), whole);
    }

    #[test]
    fn divisions_apply_in_turn_to_the_same_text() {
        let old = "é".repeat(40);
        let comparison = Comparison {
            splices: vec![
                TextSplice {
                    at: 2,
                    delete: 3,
                    insert: "ü".repeat(200),
                },
                TextSplice {
                    at: 20,
                    delete: 1,
                    insert: String::new(),
                },
                TextSplice {
                    at: 30,
                    delete: 0,
                    insert: "z".repeat(90),
                },
            ],
            replaced: false,
            limit_passed: false,
        };
        let whole = apply(&old, &comparison.splices);
        let divisions = divide(comparison.splices, 96);
        assert!(divisions.len() > 3);
        let mut text = old;
        for division in &divisions {
            text = apply(&text, division);
        }
        assert_eq!(text, whole);
    }

    #[test]
    fn folding_round_trips_a_consistent_text() {
        for text in [
            "plain\ntext\n",
            "\u{feff}marked\n",
            "dos\r\ntext\r\n",
            "\u{feff}both\r\n",
            "a lone\rreturn\n",
            "",
        ] {
            let (folded, style) = TextStyle::fold(text);
            assert!(!folded.contains("\r\n") && !folded.starts_with('\u{feff}'));
            assert_eq!(style.restore(&folded), text);
        }
    }

    #[test]
    fn a_flip_folds_to_the_same_text() {
        let (lf, _) = TextStyle::fold("one\ntwo\n");
        let (crlf, style) = TextStyle::fold("one\r\ntwo\r\n");
        assert_eq!(lf, crlf);
        assert_eq!(style.line_ending, LineEnding::CrLf);
    }

    #[test]
    fn mixed_endings_are_said_to_be_mixed() {
        let (folded, style) = TextStyle::fold("a\r\nb\r\nc\n");
        assert_eq!(folded, "a\nb\nc\n");
        assert!(style.mixed);
        assert_eq!(style.line_ending, LineEnding::CrLf);
    }
}
