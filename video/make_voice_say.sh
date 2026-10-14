#!/bin/bash
# Generate the cue-aligned, dramatic voice-over with macOS `say`, then warm it up.
# Produces voiceover.aiff.
#
# Usage:   ./make_voice_say.sh [VOICE] [RATE]
#   e.g.   ./make_voice_say.sh "Tom" 150      (download Enhanced voices for best quality)
#          ./make_voice_say.sh "Alex" 150
#
# say_lines.txt has ONE line per on-screen caption, with a clear pause between
# each — so after you send me voiceover.aiff I can detect each line's real timing
# and rebuild the video + captions to match it exactly.
set -e
cd "$(dirname "$0")"
VOICE="${1:-Alex}"
RATE="${2:-150}"

if [ ! -f say_lines.txt ]; then echo "say_lines.txt missing (run from the video folder)."; exit 1; fi

echo "Generating dramatic voice with '$VOICE' at rate $RATE ..."
say -v "$VOICE" -r "$RATE" -o /tmp/defender_raw.aiff -f say_lines.txt

if command -v ffmpeg >/dev/null 2>&1; then
  ./humanize_audio.sh /tmp/defender_raw.aiff voiceover.aiff
else
  cp /tmp/defender_raw.aiff voiceover.aiff
  echo "ffmpeg not found - skipped warm-up. Install with: brew install ffmpeg"
fi

DUR=$( (command -v ffprobe >/dev/null 2>&1 && ffprobe -v error -show_entries format=duration -of csv=p=0 voiceover.aiff) || echo "?")
echo ""
echo "Done -> voiceover.aiff   (length: ${DUR}s)"
echo ""
echo "NEXT: send voiceover.aiff back to me (it's already in a connected folder),"
echo "and I'll re-time the video + captions to match it exactly, then return the"
echo "final synced MP4. Do NOT run add_voice.sh yet - the dramatic voice is longer"
echo "than the current video, so it needs re-timing first."
