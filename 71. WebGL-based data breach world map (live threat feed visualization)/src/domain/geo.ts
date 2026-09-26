/**
 * AEGIS-SENTINEL — Geodata: hub cities + land-mask dots for the globe.
 */

export interface CityHub {
  name: string
  country: string
  lat: number
  lon: number
  weight: number // relative likelihood of appearing in events
}

/** Major internet-exchange / financial hubs — event origins & targets. */
export const CITY_HUBS: CityHub[] = [
  { name: 'New York',      country: 'US', lat: 40.7128,  lon: -74.006,  weight: 9 },
  { name: 'Washington DC', country: 'US', lat: 38.9072,  lon: -77.0369, weight: 6 },
  { name: 'Silicon Valley',country: 'US', lat: 37.3875,  lon: -122.0575,weight: 7 },
  { name: 'Chicago',       country: 'US', lat: 41.8781,  lon: -87.6298, weight: 4 },
  { name: 'London',        country: 'GB', lat: 51.5072,  lon: -0.1276,  weight: 8 },
  { name: 'Frankfurt',     country: 'DE', lat: 50.1109,  lon: 8.6821,   weight: 7 },
  { name: 'Amsterdam',     country: 'NL', lat: 52.3676,  lon: 4.9041,   weight: 6 },
  { name: 'Paris',         country: 'FR', lat: 48.8566,  lon: 2.3522,   weight: 5 },
  { name: 'Zurich',        country: 'CH', lat: 47.3769,  lon: 8.5417,   weight: 3 },
  { name: 'Stockholm',     country: 'SE', lat: 59.3293,  lon: 18.0686,  weight: 3 },
  { name: 'Moscow',        country: 'RU', lat: 55.7558,  lon: 37.6173,  weight: 6 },
  { name: 'Singapore',     country: 'SG', lat: 1.3521,   lon: 103.8198, weight: 7 },
  { name: 'Hong Kong',     country: 'HK', lat: 22.3193,  lon: 114.1694, weight: 5 },
  { name: 'Tokyo',         country: 'JP', lat: 35.6762,  lon: 139.6503, weight: 7 },
  { name: 'Seoul',         country: 'KR', lat: 37.5665,  lon: 126.978,  weight: 5 },
  { name: 'Beijing',       country: 'CN', lat: 39.9042,  lon: 116.4074, weight: 5 },
  { name: 'Shanghai',      country: 'CN', lat: 31.2304,  lon: 121.4737, weight: 5 },
  { name: 'Mumbai',        country: 'IN', lat: 19.076,   lon: 72.8777,  weight: 5 },
  { name: 'Bangalore',     country: 'IN', lat: 12.9716,  lon: 77.5946,  weight: 4 },
  { name: 'Dubai',         country: 'AE', lat: 25.2048,  lon: 55.2708,  weight: 4 },
  { name: 'Tel Aviv',      country: 'IL', lat: 32.0853,  lon: 34.7818,  weight: 4 },
  { name: 'São Paulo',     country: 'BR', lat: -23.5505, lon: -46.6333, weight: 4 },
  { name: 'Mexico City',   country: 'MX', lat: 19.4326,  lon: -99.1332, weight: 3 },
  { name: 'Sydney',        country: 'AU', lat: -33.8688, lon: 151.2093, weight: 4 },
  { name: 'Johannesburg',  country: 'ZA', lat: -26.2041, lon: 28.0473,  weight: 3 },
  { name: 'Lagos',         country: 'NG', lat: 6.5244,   lon: 3.3792,   weight: 3 },
  { name: 'Toronto',       country: 'CA', lat: 43.6532,  lon: -79.3832, weight: 4 },
  { name: 'Warsaw',        country: 'PL', lat: 52.2297,  lon: 21.0122,  weight: 3 },
  { name: 'Istanbul',      country: 'TR', lat: 41.0082,  lon: 28.9784,  weight: 3 },
  { name: 'Kyiv',          country: 'UA', lat: 50.4501,  lon: 30.5234,  weight: 3 },
] as CityHub[]

/**
 * Coarse equirectangular land mask (36×72 grid, 1 = land).
 * Encoded as row strings for compactness — lat from +82.5°N to -82.5°S.
 */
const LAND_MASK_ROWS: string[] = [
  '........................................................................',
  '..######..........................................................####..',
  '.#########...................................................#########.',
  '..##########...........####...........................#############....',
  '...###########.......#########......###############################.....',
  '....#############..############..##################################.....',
  '.....######################################################.##########..',
  '.....################################.#######################..#####..',
  '......###############################..######################...####...',
  '.......#############################...#######################..........',
  '.......###########################.....######################..........',
  '........#########################.......#####################...........',
  '........########################........####################............',
  '.........######################..........###################............',
  '.........####################............##################.............',
  '..........###################.............########.########.............',
  '..........##################...............######...######..............',
  '...........################...............#######...#######.............',
  '...........##############.................########.########.............',
  '............############.................############.####..............',
  '............###########..................#############.###..............',
  '.............##########..................##############.##..............',
  '.............#########..................###############.................',
  '..............########..................################...............',
  '..............#######...................########.########...............',
  '...............#####....................#########..#######..............',
  '...............####.....................#########...######..............',
  '................###......................#######....#####...............',
  '................###......................######.....#####...............',
  '.................##......................#####......####................',
  '.................#........................####........##................',
  '..................#.........................##.........#................',
  '........................................................................',
  '........................................................................',
  '........................................................................',
  '........................................................................',
]

/** Deterministic PRNG (mulberry32) so demos are reproducible. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export interface LandDot { lat: number; lon: number }

/** Sample the land mask into lat/lon dots for the WebGL point-cloud continents. */
export function buildLandDots(): LandDot[] {
  const dots: LandDot[] = []
  const rows = LAND_MASK_ROWS.length // 36
  for (let r = 0; r < rows; r++) {
    const row = LAND_MASK_ROWS[r]
    const lat = 82.5 - (r + 0.5) * (165 / rows)
    for (let c = 0; c < 72; c++) {
      if (row[c] === '#') {
        const lon = -180 + (c + 0.5) * (360 / 72)
        // Jitter subcells to soften the grid look
        const sub = 3
        for (let sy = 0; sy < sub; sy++) {
          for (let sx = 0; sx < sub; sx++) {
            dots.push({
              lat: lat + (sy / sub - 0.5) * (165 / rows) * 0.9,
              lon: lon + (sx / sub - 0.5) * (360 / 72) * 0.9,
            })
          }
        }
      }
    }
  }
  return dots
}
