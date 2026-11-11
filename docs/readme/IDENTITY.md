# Seaward identity

**One idea:** a sea chart of one machine's approaches: which ports can really be reached from outside, and the rule that decides each one.

## The product

- **Look:** a chart. Open water on the left, the shoreline where the firewall stands, the machine as land on the right, and every port a lane drawn in from the sea. Paper and ink by day (`#f8f6ef`, `#16212b`), deep water by night (`#0a141f`).
- **Colour, 60/30/10:** paper or water dominant, ink for everything you read, and the chart's two tints: buff for land (`#f1e8cb`, at night `#23211a`) and shallow-water blue with one contour line (`#cfe5f1` and `#7fb0cc`, at night `#10304a` and `#2f6688`). One overprint magenta (`#c2136b` by day, `#ff4f9b` by night) that is never used for anything but "the firewall tool's list says otherwise".
- **Type:** Instrument Sans for everything you read: narrowed and semibold in the verdict, italic for the sea and for port numbers, which are set the way a chart sets a depth. Spline Sans Mono for whatever came from the machine: rules, addresses, commands.
- **Voice:** plain and counted, the way a pilot reads a chart aloud. It says what is reachable and what the firewall tool believes, and it says so when it cannot know: "7 ports can be reached from outside. ufw allows only 4 of them.", "Reachable from the internet. ufw does not allow it.", "The firewall rules could not be read, so nothing is decided.", "The kernel shows them to root only. Run it again with sudo."
- **Signature details:**
  - The headline is a sentence that counts, and the half of it the firewall tool would not agree with is overprinted in magenta.
  - One lane for each port, drawn by what happens to a packet: a full line when anyone can reach it, a broken one when only some senders can, a dotted one when it is not decided, a bar where the firewall stops it, and a short lane on land for a port that listens on this machine only.
  - Open a lane and its passage is drawn as an inset plan: the packet's way through the machine, step by step, with every rule quoted as the machine holds it.
  - The cartouche names the chart, "Approaches to" and the host, and the fine print sits in the lower margin: the caution, the firewall tool's own list, the symbols in use.
  - What could not be read is hatched in heavy ink. It is never drawn as closed.
  - The mark: one lane through a gap in the shoreline, ending at a berth.

## The README images

- **Glass:** the README joins the Glass family of the author's other repositories, and brings its own ground: the real pages and terminals lie as land on a chart. Depth contours ring each pane, and the soundings in the water are the sample server's real port numbers. Deep water melts into GitHub's dark page, chart paper into its white one. Every image ships dark and light, wide and phone, and the dark images show the page in its night theme, so nothing glares.
- **Staging:** real captures of the demo page reading the sample server `shop-1`, and of command-line sessions run for real in a throwaway folder. Each feature panel lifts one element out of its screen: the counted verdict of a scan, the two rules `seaward why 5432` quotes, the one line the kernel lab prints, the sentence a scan without root opens with, the head of the collector script.
- **Motion:** only the hero moves, in a loop at 12 frames a second. It opens on the finished picture, the chart with the lane of port 5432 lifted out, and holds it. The lane settles back and is opened, the way a visitor opens it: the passage draws the packet's way rule by rule, and its track lifts out, ending in "open". Then the fixed server is chosen in the page's own sample switcher, the terminal beside it shows the same scan of that server, and the new verdict lifts out: "4 ports can be reached from outside, all allowed by ufw." The panes and the chart under them lie still, so their text stays sharp; only what is lifted rises and sinks a little. The page's own animation is stepped by hand, so every build photographs the same moments.
- **Copy:** Instrument Sans in the images, set flush left beside the glass, with the command as a small line of Spline Sans Mono above each heading. Three true numbers stand under each panel as italic soundings over a double hairline; whatever the tool prints is taken from what it printed during the build, never typed in. The band of five figures is drawn from `src/numbers.json`.
- **Source:** `make shots` builds the binary and the demo and runs `docs/readme/src/build.sh`, which captures the terminals and the page (`capture.cjs`) and renders every scene (`render.cjs`, `scene.js`, `layouts.js`); `loop.py` packs the hero's frames into its loop. `./build.sh numbers` renders the band of five figures again and nothing else. `social.png` is the plate for the repository's social preview and for the demo's link card.
