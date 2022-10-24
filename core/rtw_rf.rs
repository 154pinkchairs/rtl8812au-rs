/******************************************************************************
 *
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 *                                        
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110, USA
 *
 *
 ******************************************************************************/

use crate::rtw_hal::rtw_hal;

struct ch_freq {
    ch: u32,
    freq: u32,
}

struct ch_freq ch_freq_map[] = [
    ch_freq { ch: 1, freq: 2412 },
    ch_freq { ch: 2, freq: 2417 },
    ch_freq { ch: 3, freq: 2422 },
    ch_freq { ch: 4, freq: 2427 },
    ch_freq { ch: 5, freq: 2432 },
    ch_freq { ch: 6, freq: 2437 },
    ch_freq { ch: 7, freq: 2442 },
    ch_freq { ch: 8, freq: 2447 },
    ch_freq { ch: 9, freq: 2452 },
    ch_freq { ch: 10, freq: 2457 },
    ch_freq { ch: 11, freq: 2462 },
    ch_freq { ch: 12, freq: 2467 },
    ch_freq { ch: 13, freq: 2472 },
    ch_freq { ch: 14, freq: 2484 },
    /*  UNII */
    ch_freq { ch: 36, freq: 5180 },
    ch_freq { ch: 40, freq: 5200 },
    ch_freq { ch: 44, freq: 5220 },
    ch_freq { ch: 48, freq: 5240 },
    ch_freq { ch: 52, freq: 5260 },
    ch_freq { ch: 56, freq: 5280 },
    ch_freq { ch: 60, freq: 5300 },
    ch_freq { ch: 64, freq: 5320 },
    ch_freq { ch: 149, freq: 5745 },
    ch_freq { ch: 153, freq: 5765 },
    ch_freq { ch: 157, freq: 5785 },
    ch_freq { ch: 161, freq: 5805 },
    ch_freq { ch: 165, freq: 5825 },
    ch_freq { ch: 167, freq: 5835 },
    ch_freq { ch: 169, freq: 5845 },
    ch_freq { ch: 171, freq: 5855 },
    ch_freq { ch: 173, freq: 5865 },
    /* HiperLAN2 */
    ch_freq { ch: 100, freq: 5500},
    ch_freq { ch: 104, freq: 5520},
    ch_freq { ch: 108, freq: 5540},
    ch_freq { ch: 112, freq: 5560},
    ch_freq { ch: 116, freq: 5580},
    ch_freq { ch: 120, freq: 5600},
    ch_freq { ch: 124, freq: 5620},
    ch_freq { ch: 128, freq: 5640},
    ch_freq { ch: 132, freq: 5660},
    ch_freq { ch: 136, freq: 5680},
    ch_freq { ch: 140, freq: 5700},
    /* Japan MMAC */
    ch_freq { ch: 34, freq: 5170},
    ch_freq { ch: 38, freq: 5190},
    ch_freq { ch: 42, freq: 5210},
    ch_freq { ch: 46, freq: 5230},
    /*  Japan */
    ch_freq { ch: 184, freq: 4920},
    ch_freq { ch: 188, freq: 4940},
    ch_freq { ch: 192, freq: 4960},
    ch_freq { ch: 196, freq: 4980},
    ch_freq { ch: 208, freq: 5040},/* Japan, means J08 */
    ch_freq { ch: 212, freq: 5060},/* Japan, means J12 */
    ch_freq { ch: 216, freq: 5080},/* Japan, means J16 */
];

fn rtw_ch2freq(channel: u32) -> u32 {
    let mut freq = 0;
    for ch_freq in ch_freq_map.iter() {
        if channel == ch_freq.ch {
            freq = ch_freq.freq;
            break;
        }
    }
    if freq == 0 {
        freq = 2412;
    }
    freq
}

fn rtw_freq2ch(freq: u32) -> u32 {
    let mut ch = 0;
    for ch_freq in ch_freq_map.iter() {
        if freq == ch_freq.freq {
            ch = ch_freq.ch;
            break;
        }
    }
    if ch == 0 {
        ch = 1;
    }
    ch
}
