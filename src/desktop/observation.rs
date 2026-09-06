use super::Operation;
use crate::win32::{
    display::Rect,
    screen::{CaptureFrame, CaptureMetadata},
};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_FRAMES: usize = 4;
const RETENTION: Duration = Duration::from_secs(120);
const TILE: u32 = 32;
const MAX_REGIONS: usize = 256;

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ComparisonStatus {
    NotRequested,
    Compared,
    BaselineMissing,
    BaselineMismatch,
}

#[derive(Debug, Serialize)]
pub(crate) struct Changes {
    pub status: ComparisonStatus,
    pub baseline_id: Option<String>,
    pub gap: bool,
    pub reason: Option<String>,
    pub changed: Option<bool>,
    pub changed_pixels: Option<u64>,
    pub regions: Vec<Rect>,
    pub regions_coalesced: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct Retention {
    pub retained: bool,
    pub lifetime: &'static str,
    pub max_frames: usize,
    pub max_bytes: usize,
    pub ttl_ms: u64,
    pub reason: Option<String>,
}

struct StoredFrame {
    id: String,
    metadata: CaptureMetadata,
    bgra: Vec<u8>,
    inserted: Instant,
}

#[derive(Default)]
pub(crate) struct FrameStore {
    frames: VecDeque<StoredFrame>,
}

impl FrameStore {
    pub fn observe(
        &mut self,
        frame: &CaptureFrame,
        baseline: Option<&str>,
        operation: &Operation,
    ) -> Result<(String, Changes, Retention)> {
        operation.check()?;
        self.frames
            .retain(|frame| frame.inserted.elapsed() < RETENTION);
        let mut changes = Changes {
            status: ComparisonStatus::NotRequested,
            baseline_id: baseline.map(str::to_owned),
            gap: false,
            reason: None,
            changed: None,
            changed_pixels: None,
            regions: Vec::new(),
            regions_coalesced: false,
        };
        if let Some(id) = baseline {
            match self.frames.iter().find(|frame| frame.id == id) {
                None => {
                    changes.status = ComparisonStatus::BaselineMissing;
                    changes.gap = true;
                    changes.reason = Some("The baseline expired, was evicted, was not retained, or belongs to another connection. Earlier pixels cannot be reconstructed.".into());
                }
                Some(previous) if !compatible(&previous.metadata, &frame.metadata) => {
                    changes.status = ComparisonStatus::BaselineMismatch;
                    changes.gap = true;
                    changes.reason = Some("The target identity, session, origin, dimensions, scaling or monitor layout changed.".into());
                }
                Some(previous) => {
                    let (pixels, regions, coalesced) = compare(
                        &previous.bgra,
                        &frame.bgra,
                        frame.metadata.physical_bounds,
                        operation,
                    )?;
                    changes.status = ComparisonStatus::Compared;
                    changes.changed = Some(pixels > 0);
                    changes.changed_pixels = Some(pixels);
                    changes.regions = regions;
                    changes.regions_coalesced = coalesced;
                }
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let retained = frame.bgra.len() <= MAX_RETAINED_BYTES;
        if retained {
            let mut bytes: usize = self.frames.iter().map(|frame| frame.bgra.len()).sum();
            while self.frames.len() >= MAX_FRAMES || bytes + frame.bgra.len() > MAX_RETAINED_BYTES {
                if let Some(old) = self.frames.pop_front() {
                    bytes -= old.bgra.len();
                } else {
                    break;
                }
            }
            let mut bgra = Vec::new();
            bgra.try_reserve_exact(frame.bgra.len())
                .context("Cannot retain the capture baseline")?;
            bgra.extend_from_slice(&frame.bgra);
            self.frames.push_back(StoredFrame {
                id: id.clone(),
                metadata: frame.metadata.clone(),
                bgra,
                inserted: Instant::now(),
            });
        }
        Ok((id, changes, Retention {
            retained, lifetime: "this_stdio_connection", max_frames: MAX_FRAMES,
            max_bytes: MAX_RETAINED_BYTES, ttl_ms: RETENTION.as_millis() as u64,
            reason: (!retained).then(|| "This frame exceeds the bounded baseline cache; it cannot be used as a later baseline.".into()),
        }))
    }
}

fn compatible(previous: &CaptureMetadata, current: &CaptureMetadata) -> bool {
    previous.target == current.target
        && previous.session.session_id == current.session.session_id
        && previous.session.desktop == current.session.desktop
        && previous.physical_bounds == current.physical_bounds
        && previous.scale_x == current.scale_x
        && previous.scale_y == current.scale_y
        && previous.geometry == current.geometry
}

fn compare(
    previous: &[u8],
    current: &[u8],
    bounds: Rect,
    operation: &Operation,
) -> Result<(u64, Vec<Rect>, bool)> {
    let expected = crate::win32::screen::validate_allocation(bounds.width, bounds.height)?;
    if previous.len() != expected || current.len() != expected {
        anyhow::bail!("Baseline pixel buffer does not match its dimensions");
    }
    let mut changed_pixels = 0;
    let mut regions: Vec<Rect> = Vec::new();
    let mut coalesced = false;
    for tile_y in (0..bounds.height).step_by(TILE as usize) {
        operation.check()?;
        let height = TILE.min(bounds.height - tile_y);
        let mut run_start = None;
        for tile_x in (0..bounds.width).step_by(TILE as usize) {
            let width = TILE.min(bounds.width - tile_x);
            let mut changed = false;
            for y in tile_y..tile_y + height {
                for x in tile_x..tile_x + width {
                    let index = (y as usize * bounds.width as usize + x as usize) * 4;
                    // GDI alpha is undefined for some surfaces. Compare only BGR.
                    if previous[index..index + 3] != current[index..index + 3] {
                        changed_pixels += 1;
                        changed = true;
                    }
                }
            }
            if changed && run_start.is_none() {
                run_start = Some(tile_x);
            }
            if (!changed || tile_x + width == bounds.width) && run_start.is_some() {
                let start = run_start.take().expect("checked tile run");
                let end = if changed { tile_x + width } else { tile_x };
                let region = Rect {
                    x: i32::try_from(i64::from(bounds.x) + i64::from(start))?,
                    y: i32::try_from(i64::from(bounds.y) + i64::from(tile_y))?,
                    width: end - start,
                    height,
                };
                add_region(&mut regions, region, &mut coalesced);
            }
        }
    }
    Ok((changed_pixels, regions, coalesced))
}

fn add_region(regions: &mut Vec<Rect>, region: Rect, coalesced: &mut bool) {
    if *coalesced {
        regions[0] = union(regions[0], region);
        return;
    }
    if let Some(previous) = regions.iter_mut().rev().find(|previous| {
        previous.x == region.x
            && previous.width == region.width
            && previous.bottom() == i64::from(region.y)
    }) {
        previous.height += region.height;
        return;
    }
    if regions.len() >= MAX_REGIONS {
        let envelope = regions.iter().copied().fold(region, union);
        regions.clear();
        regions.push(envelope);
        *coalesced = true;
    } else {
        regions.push(region);
    }
}

fn union(left: Rect, right: Rect) -> Rect {
    let x = left.x.min(right.x);
    let y = left.y.min(right.y);
    Rect {
        x,
        y,
        width: (left.right().max(right.right()) - i64::from(x)) as u32,
        height: (left.bottom().max(right.bottom()) - i64::from(y)) as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_map_tiles_back_to_negative_physical_coordinates() {
        let bounds = Rect {
            x: -1920,
            y: -200,
            width: 64,
            height: 64,
        };
        let before = vec![0; 64 * 64 * 4];
        let mut after = before.clone();
        after[(33 * 64 + 34) * 4] = 255;
        let (pixels, regions, coalesced) =
            compare(&before, &after, bounds, &Operation::new(1000).unwrap()).unwrap();
        assert_eq!(pixels, 1);
        assert_eq!(
            regions,
            vec![Rect {
                x: -1888,
                y: -168,
                width: 32,
                height: 32
            }]
        );
        assert!(!coalesced);
    }

    #[test]
    fn alpha_changes_are_not_desktop_content_changes() {
        let (pixels, regions, _) = compare(
            &[0, 0, 0, 0],
            &[0, 0, 0, 255],
            Rect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            &Operation::new(1000).unwrap(),
        )
        .unwrap();
        assert_eq!(pixels, 0);
        assert!(regions.is_empty());
    }

    #[test]
    fn comparison_rejects_wrong_buffer_lengths_and_obeys_cancellation() {
        let operation = Operation::new(1000).unwrap();
        let bounds = Rect {
            x: 0,
            y: 0,
            width: 2,
            height: 2,
        };
        assert!(compare(&[0], &[0], bounds, &operation).is_err());
        operation.cancellation.cancel().unwrap();
        assert!(compare(&[0; 16], &[0; 16], bounds, &operation).is_err());
    }

    #[test]
    fn region_retention_coalesces_instead_of_growing_without_bound() {
        let mut regions = Vec::new();
        let mut coalesced = false;
        for x in 0..300 {
            add_region(
                &mut regions,
                Rect {
                    x: x * 2,
                    y: 0,
                    width: 1,
                    height: 1,
                },
                &mut coalesced,
            );
        }
        assert!(coalesced);
        assert_eq!(
            regions,
            vec![Rect {
                x: 0,
                y: 0,
                width: 599,
                height: 1
            }]
        );
    }

    #[test]
    fn comparison_reports_baseline_mismatch_expiry_and_eviction_gaps() {
        let operation = Operation::new(5000).unwrap();
        let bounds = Rect {
            x: -10,
            y: 20,
            width: 1,
            height: 1,
        };
        let mut store = FrameStore::default();
        let frame = CaptureFrame::fixture(bounds, vec![0; 4]);
        let (first, _, retention) = store.observe(&frame, None, &operation).unwrap();
        assert!(retention.retained);
        let (_, changes, _) = store.observe(&frame, Some(&first), &operation).unwrap();
        assert!(matches!(changes.status, ComparisonStatus::Compared));
        assert_eq!(changes.changed, Some(false));
        drop(frame);

        let moved = CaptureFrame::fixture(Rect { x: -20, ..bounds }, vec![0; 4]);
        let (_, changes, _) = store.observe(&moved, Some(&first), &operation).unwrap();
        assert!(matches!(changes.status, ComparisonStatus::BaselineMismatch));
        assert!(changes.gap);
        for _ in 0..MAX_FRAMES {
            store.observe(&moved, None, &operation).unwrap();
        }
        let (last, changes, _) = store.observe(&moved, Some(&first), &operation).unwrap();
        assert!(matches!(changes.status, ComparisonStatus::BaselineMissing));
        assert!(changes.gap);
        assert!(store.frames.len() <= MAX_FRAMES);
        for stored in &mut store.frames {
            stored.inserted = Instant::now() - RETENTION - Duration::from_secs(1);
        }
        let (_, changes, _) = store.observe(&moved, Some(&last), &operation).unwrap();
        assert!(matches!(changes.status, ComparisonStatus::BaselineMissing));
        assert!(changes.gap);
    }
}
