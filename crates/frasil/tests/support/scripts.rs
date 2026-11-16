//! Generated text for the rewrite tests and measurements: prose, play-style
//! dialogue with `@Name` cues, and a 20-word near-worst case. Nothing here
//! is a real script; the same seed gives the same text.

#![allow(dead_code)]

/// A small generator (xorshift64*), so the text needs no dependency.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    /// An index below `bound`, low ones far likelier: roughly how often
    /// words occur in a language.
    pub fn zipf(&mut self, bound: usize) -> usize {
        let low = self.below(bound).max(1);
        self.below(low)
    }
}

/// How a text is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Paragraphs wrapped at 72 columns, from a vocabulary of thousands.
    Prose,
    /// A play: scene headings, `@Name` cues, speeches, stage directions and
    /// stock lines that repeat.
    Play,
    /// Cues and sentences from 20 words: near the worst case for a
    /// character diff.
    Worst,
}

impl Kind {
    pub const ALL: [Self; 3] = [Self::Prose, Self::Play, Self::Worst];

    pub fn name(self) -> &'static str {
        match self {
            Self::Prose => "prose",
            Self::Play => "play",
            Self::Worst => "worst",
        }
    }
}

const ONSETS: [&str; 18] = [
    "b", "br", "ch", "d", "f", "g", "gr", "j", "l", "m", "n", "p", "qu", "r", "s", "t", "tr", "v",
];
const NUCLEI: [&str; 12] = [
    "a", "ai", "e", "é", "ou", "i", "o", "u", "eau", "an", "on", "è",
];
const CODAS: [&str; 8] = ["", "", "", "r", "s", "n", "l", "t"];

fn vocabulary(rng: &mut Rng, size: usize) -> Vec<String> {
    (0..size)
        .map(|_| {
            let mut word = String::new();
            for _ in 0..=rng.below(3) {
                word.push_str(ONSETS[rng.below(ONSETS.len())]);
                word.push_str(NUCLEI[rng.below(NUCLEI.len())]);
            }
            word.push_str(CODAS[rng.below(CODAS.len())]);
            word
        })
        .collect()
}

const WORST: [&str; 20] = [
    "nothing", "to", "be", "done", "the", "road", "tree", "we", "wait", "here", "tomorrow", "he",
    "will", "come", "perhaps", "not", "today", "what", "shall", "do",
];

const CUES: [&str; 6] = [
    "@Vladimir",
    "@Estragon",
    "@Pozzo",
    "@Lucky",
    "@Boy",
    "@Marguerite",
];

const STOCK: [&str; 8] = [
    "Yes.",
    "No.",
    "Why?",
    "What?",
    "Let us go.",
    "They do not move.",
    "(Silence.)",
    "I do not know.",
];

/// Words joined into sentences, wrapped at `width` columns.
fn wrapped(rng: &mut Rng, words: &[String], count: usize, width: usize, out: &mut String) {
    let mut column = 0;
    let mut sentence = 0;
    for index in 0..count {
        let mut word = words[rng.zipf(words.len())].clone();
        if sentence == 0 {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                word = first.to_uppercase().chain(chars).collect();
            }
        }
        sentence += 1;
        if index + 1 == count || sentence > 6 + rng.below(12) {
            word.push(if rng.below(5) == 0 { '?' } else { '.' });
            sentence = 0;
        } else if rng.below(9) == 0 {
            word.push(',');
        }
        let length = word.chars().count();
        if column > 0 && column + 1 + length > width {
            out.push('\n');
            column = 0;
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(&word);
        column += length;
    }
    out.push('\n');
}

/// A text of about `bytes` bytes.
pub fn script(kind: Kind, bytes: usize, seed: u64) -> String {
    let mut rng = Rng::new(seed);
    let words: Vec<String> = match kind {
        Kind::Worst => WORST.iter().map(ToString::to_string).collect(),
        _ => vocabulary(&mut Rng::new(0xF4A5), 6000),
    };
    let mut out = String::with_capacity(bytes + 256);
    let mut scene = 0;
    while out.len() < bytes {
        match kind {
            Kind::Prose => {
                let count = 30 + rng.below(90);
                wrapped(&mut rng, &words, count, 72, &mut out);
                out.push('\n');
            }
            Kind::Play | Kind::Worst => {
                if out.is_empty() || rng.below(40) == 0 {
                    scene += 1;
                    out.push_str(&format!("# Scene {scene}\n\n"));
                }
                out.push_str(CUES[rng.below(CUES.len())]);
                out.push('\n');
                if kind == Kind::Play && rng.below(4) == 0 {
                    out.push_str(STOCK[rng.below(STOCK.len())]);
                    out.push('\n');
                } else {
                    let count = 4 + rng.below(40);
                    wrapped(&mut rng, &words, count, 60, &mut out);
                }
                out.push('\n');
            }
        }
    }
    out
}

/// A byte offset of the start of a word about `share` of the way in.
fn word_at(text: &str, share: f64) -> usize {
    let mut at = (text.len() as f64 * share) as usize;
    while !text.is_char_boundary(at) {
        at += 1;
    }
    match text[at..].find(' ') {
        Some(space) => at + space + 1,
        None => 0,
    }
}

/// The word at a byte offset replaced.
fn replace_word(text: &str, at: usize, with: &str) -> String {
    let end = at + text[at..].find([' ', '\n']).unwrap_or(0);
    format!("{}{with}{}", &text[..at], &text[end..])
}

/// One word changed, in the middle.
pub fn one_word(text: &str) -> String {
    replace_word(text, word_at(text, 0.5), "changed")
}

/// One word changed every `every_kb` kilobytes.
pub fn scattered(text: &str, every_kb: usize) -> String {
    let step = every_kb * 1024;
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while from + step < text.len() {
        let mut at = from + step;
        while !text.is_char_boundary(at) {
            at += 1;
        }
        let Some(space) = text[at..].find(' ') else {
            break;
        };
        let word = at + space + 1;
        let end = word + text[word..].find([' ', '\n']).unwrap_or(0);
        out.push_str(&text[from..word]);
        out.push_str("changed");
        from = end;
    }
    out.push_str(&text[from..]);
    out
}

/// Each paragraph joined and wrapped again at `width`: what a formatter does.
pub fn reflow(text: &str, width: usize) -> String {
    let mut out = String::with_capacity(text.len());
    for block in text.split("\n\n") {
        let mut lines = block.lines();
        if block.starts_with('@') || block.starts_with('#') {
            out.push_str(lines.next().unwrap_or_default());
            out.push('\n');
        }
        rewrap(&lines.collect::<Vec<_>>().join(" "), width, &mut out);
        out.push_str("\n\n");
    }
    out.truncate(out.trim_end_matches('\n').len());
    out.push('\n');
    out
}

fn rewrap(block: &str, width: usize, out: &mut String) {
    let mut column = 0;
    for word in block.split(' ').filter(|word| !word.is_empty()) {
        let length = word.chars().count();
        if column > 0 && column + 1 + length > width {
            out.push('\n');
            column = 0;
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += length;
    }
}

/// LF flipped to CRLF.
pub fn crlf(text: &str) -> String {
    text.replace('\n', "\r\n")
}
