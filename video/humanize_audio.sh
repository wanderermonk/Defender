#!/bin/bash
# Post-process a voice-over so it sounds warmer and more "recorded" (less TTS).
# Works on any TTS output (say, ElevenLabs, etc).
# Usage:  ./humanize_audio.sh input.aiff output.aiff
#   in :  raw voice (aiff/mp3/wav)
#   out:  processed voice
set -e
cd "$(dirname "$0")"
IN="${1:-/tmp/defender_raw.aiff}"
OUT="${2:-voiceover.aiff}"

if ! command -v ffmpeg >/dev/null 2>&1; then echo "Install ffmpeg: brew install ffmpeg"; exit 1; fi

# Chain, in order:
#  highpass/lowpass   - trim rumble + harsh hiss (voice band)
#  equalizer x3       - cut boxiness (300Hz), add presence (3.5kHz), air (10kHz)
#  acompressor        - even out loud/soft so it sounds "spoken", not flat
#  aecho              - a hint of room so it isn't bone-dry/robotic
#  loudnorm           - broadcast loudness (-16 LUFS), consistent level
ffmpeg -y -i "$IN" -af "\
highpass=f=80,\
lowpass=f=12000,\
equalizer=f=120:t=q:w=1.0:g=2,\
equalizer=f=300:t=q:w=1.2:g=-3,\
equalizer=f=3500:t=q:w=1.0:g=3,\
equalizer=f=10000:t=q:w=1.0:g=2,\
acompressor=threshold=-20dB:ratio=3.5:attack=10:release=220:makeup=3,\
aecho=0.8:0.85:55:0.12,\
loudnorm=I=-15:TP=-1.5:LRA=12" \
"$OUT"

echo "Warmed voice -> $OUT"
