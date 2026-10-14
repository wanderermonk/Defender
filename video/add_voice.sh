#!/bin/bash
# Patch a voice-over track onto the Defender tutorial video.
# Usage:  ./add_voice.sh voiceover.aiff        (or voiceover.mp3 / .wav)
# Output: Defender_tutorial_voiced.mp4
set -e
cd "$(dirname "$0")"

AUDIO="${1:-voiceover.aiff}"
VIDEO="Defender_tutorial.mp4"
OUT="Defender_tutorial_voiced.mp4"

if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "ffmpeg not found. Install it first:  brew install ffmpeg"; exit 1
fi
if [ ! -f "$AUDIO" ]; then echo "Audio file '$AUDIO' not found."; exit 1; fi
if [ ! -f "$VIDEO" ]; then echo "Video '$VIDEO' not found (run from the video folder)."; exit 1; fi

# durations (for a friendly heads-up about drift)
vdur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$VIDEO")
adur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$AUDIO")
echo "video: ${vdur}s   voice: ${adur}s"

# mux: keep the video stream as-is, encode the voice to AAC.
# no -shortest, so nothing gets cut; the file length = the longer of the two.
ffmpeg -y -i "$VIDEO" -i "$AUDIO" \
  -map 0:v:0 -map 1:a:0 \
  -c:v copy -c:a aac -b:a 192k \
  "$OUT"

echo "Done -> $OUT"
echo "If the voice and captions drift apart, send me the voice file and I'll re-time the animation to match it exactly."
