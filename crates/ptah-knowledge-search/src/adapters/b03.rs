use crate::{AnchoredTextInput, D03Error};
use ptah_archive_decomposition::{AnchoredText, SourceAnchor};

pub(crate) fn to_b03(spans: &[AnchoredTextInput]) -> Result<Vec<AnchoredText>, D03Error> {
    spans
        .iter()
        .map(|span| {
            span.validate()?;
            Ok(AnchoredText {
                text: span.text.clone(),
                anchor: SourceAnchor {
                    source_revision_ref: span.object_revision_ref.clone(),
                    byte_start: span.byte_start,
                    byte_end_exclusive: span.byte_end_exclusive,
                    page: span.page,
                },
            })
        })
        .collect()
}
