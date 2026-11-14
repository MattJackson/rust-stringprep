//! SASLprep into a caller-owned buffer, for secrets such as passwords.

use crate::{tables, Error, ErrorCause};
use unicode_normalization::char::{canonical_combining_class, compose, decompose_compatible};
use zeroize::{Zeroize, Zeroizing};

/// Prepares `s` with the SASLprep profile ([RFC 4013][]) into `out`, as a stored string.
///
/// Unlike [`saslprep`](crate::saslprep), every intermediate buffer is zeroized before it is
/// freed or regrown, and `out` is cleared (and wiped) first and then filled with one exact-size
/// allocation, so no copy of the prepared text is left behind in freed memory. Normalization
/// follows the Unicode 3.2 data that RFC 3454 is defined against: the five CJK compatibility
/// ideographs whose decompositions were corrected after 3.2 decompose as in 3.2, and the code
/// points whose bidirectional category changed from L after 3.2 keep their 3.2 category.
/// Unassigned code points are refused in the input as well as the output (RFC 3454 §7), and an
/// empty result is an error.
///
/// [RFC 4013]: https://tools.ietf.org/html/rfc4013
pub fn saslprep_into(s: &str, out: &mut Zeroizing<String>) -> Result<(), Error> {
    out.zeroize();
    let mut chars = Zeroizing::new(Vec::new());
    for c in s.chars() {
        // 2.1 Mapping
        let c = if tables::non_ascii_space_character(c) {
            ' '
        } else {
            c
        };
        if tables::commonly_mapped_to_nothing(c) {
            continue;
        }
        if tables::unassigned_code_point(c) {
            return Err(Error(ErrorCause::ProhibitedCharacter(c)));
        }
        // 2.2 Normalization (KC): compatibility decomposition first.
        decompose_compatible(unicode_3_2_decomposition(c), |d| push_wiping(&mut chars, d));
    }
    if chars.is_empty() {
        return Err(Error(ErrorCause::EmptyString));
    }

    // Canonical ordering.
    for i in 1..chars.len() {
        let class = canonical_combining_class(chars[i]);
        if class == 0 {
            continue;
        }
        let mut j = i;
        while j > 0 && canonical_combining_class(chars[j - 1]) > class {
            chars.swap(j - 1, j);
            j -= 1;
        }
    }

    // Canonical composition, in place.
    let mut starter = None;
    let mut last_class = 0;
    let mut written = 0;
    for read in 0..chars.len() {
        let c = chars[read];
        let class = canonical_combining_class(c);
        if let Some(at) = starter {
            if last_class == 0 || last_class < class {
                if let Some(composed) = compose(chars[at], c) {
                    chars[at] = composed;
                    continue;
                }
            }
        }
        chars[written] = c;
        if class == 0 {
            starter = Some(written);
        }
        last_class = class;
        written += 1;
    }
    chars[written..].zeroize();
    chars.truncate(written);

    // 2.3 Prohibited Output
    if let Some(c) = chars.iter().copied().find(|&c| prohibited(c)) {
        return Err(Error(ErrorCause::ProhibitedCharacter(c)));
    }
    // 2.4 Bidirectional Characters
    if chars.iter().copied().any(tables::bidi_r_or_al)
        && (chars.iter().copied().any(unicode_3_2_bidi_l)
            || !chars.first().copied().is_some_and(tables::bidi_r_or_al)
            || !chars.last().copied().is_some_and(tables::bidi_r_or_al))
    {
        return Err(Error(ErrorCause::ProhibitedBidirectionalText));
    }
    // 2.5 Unassigned Code Points
    if let Some(c) = chars
        .iter()
        .copied()
        .find(|&c| tables::unassigned_code_point(c))
    {
        return Err(Error(ErrorCause::ProhibitedCharacter(c)));
    }

    let len = chars.iter().map(|c| c.len_utf8()).sum();
    out.reserve_exact(len);
    for &c in chars.iter() {
        out.push(c);
    }
    Ok(())
}

fn push_wiping(chars: &mut Zeroizing<Vec<char>>, c: char) {
    if chars.len() == chars.capacity() {
        let mut next = Zeroizing::new(Vec::with_capacity(chars.len().saturating_mul(2).max(4)));
        next.extend_from_slice(chars);
        *chars = next;
    }
    chars.push(c);
}

fn prohibited(c: char) -> bool {
    tables::non_ascii_space_character(c) /* C.1.2 */
        || tables::ascii_control_character(c) /* C.2.1 */
        || tables::non_ascii_control_character(c) /* C.2.2 */
        || tables::private_use(c) /* C.3 */
        || tables::non_character_code_point(c) /* C.4 */
        || tables::surrogate_code(c) /* C.5 */
        || tables::inappropriate_for_plain_text(c) /* C.6 */
        || tables::inappropriate_for_canonical_representation(c) /* C.7 */
        || tables::change_display_properties_or_deprecated(c) /* C.8 */
        || tables::tagging_character(c) /* C.9 */
}

/// The Unicode 3.2 decompositions of the five CJK compatibility ideographs corrected later
/// (Unicode corrigendum #4).
fn unicode_3_2_decomposition(c: char) -> char {
    match c {
        '\u{2f868}' => '\u{2136a}',
        '\u{2f874}' => '\u{5f33}',
        '\u{2f91f}' => '\u{43ab}',
        '\u{2f95f}' => '\u{7aae}',
        '\u{2f9bf}' => '\u{4d57}',
        _ => c,
    }
}

/// Bidirectional category L (RFC 3454 table D.2) as of Unicode 3.2, for the code points whose
/// category has changed since.
fn unicode_3_2_bidi_l(c: char) -> bool {
    match c {
        '\u{0cbf}'
        | '\u{0cc6}'
        | '\u{1734}'
        | '\u{2132}'
        | '\u{2800}'..='\u{28ff}'
        | '\u{302e}'..='\u{302f}' => false,
        '\u{17b4}'..='\u{17b5}'
        | '\u{1885}'..='\u{1886}'
        | '\u{1d6c1}'
        | '\u{1d6db}'
        | '\u{1d6fb}'
        | '\u{1d715}'
        | '\u{1d735}'
        | '\u{1d74f}'
        | '\u{1d76f}'
        | '\u{1d789}'
        | '\u{1d7a9}'
        | '\u{1d7c3}' => true,
        _ => tables::bidi_l(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prep(s: &str) -> Option<String> {
        let mut out = Zeroizing::new(String::new());
        saslprep_into(s, &mut out)
            .ok()
            .map(|()| out.as_str().into())
    }

    #[test]
    fn rfc4013_examples() {
        assert_eq!(prep("I\u{00ad}X").as_deref(), Some("IX"));
        assert_eq!(prep("user").as_deref(), Some("user"));
        assert_eq!(prep("USER").as_deref(), Some("USER"));
        assert_eq!(prep("\u{00aa}").as_deref(), Some("a"));
        assert_eq!(prep("\u{2168}").as_deref(), Some("IX"));
        assert_eq!(prep("\u{0007}"), None);
        assert_eq!(prep("\u{0627}1"), None);
    }

    #[test]
    fn normalization_ordering_and_composition() {
        for (input, expected) in [
            ("\u{1100}\u{1161}\u{11a8}", "\u{ac01}"),
            ("\u{0315}\u{0300}", "\u{0300}\u{0315}"),
            ("A\u{0305}\u{0300}", "A\u{0305}\u{0300}"),
            ("A\u{0315}\u{0300}", "\u{00c0}\u{0315}"),
            ("A\u{030a}\u{0301}", "\u{01fa}"),
            ("A\u{0301}\u{0327}", "\u{00c1}\u{0327}"),
            ("\u{0344}", "\u{0308}\u{0301}"),
        ] {
            assert_eq!(prep(input).as_deref(), Some(expected), "{:?}", input);
        }
    }

    #[test]
    fn unicode_3_2_profile() {
        assert_eq!(prep("\u{2f868}").as_deref(), Some("\u{2136a}"));
        assert_eq!(prep("\u{f951}").as_deref(), Some("\u{964b}"));
        assert_eq!(
            prep("\u{0627}\u{2132}\u{0628}").as_deref(),
            Some("\u{0627}\u{2132}\u{0628}")
        );
        assert_eq!(prep("\u{0627}\u{17b4}\u{0628}"), None);
    }

    #[test]
    fn empty_and_unassigned_are_refused() {
        assert_eq!(prep(""), None);
        assert_eq!(prep("\u{00ad}"), None);
        assert_eq!(prep("\u{0221}"), None);
    }

    #[test]
    fn out_is_replaced() {
        let mut out = Zeroizing::new(String::from("previous"));
        saslprep_into("x", &mut out).unwrap();
        assert_eq!(out.as_str(), "x");
    }
}
