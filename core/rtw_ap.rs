/******************************************************************************
 *
 * Copyright(c) 2007 - 2012 Realtek Corporation. All rights reserved.
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
 
use core::mem::size_of;
use core::mem::transmute;
use core::mem::zeroed;
use core::ptr::null_mut;
use core::ptr::null;
use core::mem::sizeof;
use core::ptr::write_volatile;
use core::ptr::read_volatile;
use core::slice::from_raw_parts;
use core::slice::from_raw_parts_mut;


#[cfg(CONFIG_AP_MODE)]
	pub static mut RTW_WPA_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x01];
	pub static mut WMM_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x02];
	pub static mut WPS_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x04];
	pub static mut P2P_OUI: [u8; 4] = [0x50, 0x6f, 0x9a, 0x09];
	pub static mut WFD_OUI: [u8; 4] = [0x50, 0x6f, 0x9a, 0x0a];

pub fn init_mlme_ap_info(padapter: &mut Adapter) {
	let pmlmeext = &mut padapter.mlmeextpriv;
	let pmlmepriv = &mut padapter.mlmepriv;
	let pstapriv = &mut padapter.stapriv;
	let pacl_list = &mut pstapriv.acl_list;

	_rtw_spinlock_init(&mut pmlmepriv.bcn_update_lock);

	//for ACL
	_rtw_init_queue(&mut pacl_list.acl_node_q);

	//pmlmeext->bstart_bss = _FALSE;

	start_ap_mode(padapter);
}

pub fn free_mlme_ap_info(padapter: &mut Adapter) {
	let mut irqL: irqL;
	let mut psta: *mut sta_info = null_mut();
	let pstapriv = &mut padapter.stapriv;
	let pmlmepriv = &mut padapter.mlmepriv;
	let pmlmeext = &mut padapter.mlmeextpriv;
	let pmlmeinfo = &mut pmlmeext.mlmext_info;

	//stop_ap_mode(padapter);

	pmlmepriv.update_bcn = false;
	pmlmeext.bstart_bss = false;

	rtw_sta_flush(padapter);

	pmlmeinfo.state = HW_STATE_NOLINK;

	//free_assoc_sta_resources
	rtw_free_all_stainfo(padapter);

	//free bc/mc sta_info
	psta = rtw_get_bcmc_stainfo(padapter);
	_enter_critical_bh(&mut pstapriv.sta_hash_lock, &mut irqL);
	rtw_free_stainfo(padapter, psta);
	_exit_critical_bh(&mut pstapriv.sta_hash_lock, &mut irqL);

	_rtw_spinlock_free(&mut pmlmepriv.bcn_update_lock);
}

pub fn update_BCNTIM(padapter: &mut Adapter) {
	let pmlmeinfo: &mut mlme_priv = &mut padapter.mlmepriv;
	let pstapriv: &mut sta_priv = &mut padapter.stapriv;
	let pnetwork_mlmeext: &mut WLAN_BSSID_EX = &mut pmlmeinfo.network;
	let pie: *mut u8 = pnetwork_mlmeext.IEs;

	//DBG_871X("%s\n", __FUNCTION__);

	//update TIM IE
	//if(pstapriv->tim_bitmap)
	if true {
		let mut p: *mut u8;
		let mut dst_ie: *mut u8;
		let mut premainder_ie: *mut u8 = ptr::null_mut();
		let mut pbackup_remainder_ie: *mut u8 = ptr::null_mut();
		let mut tim_bitmap_le: u16;
		let mut offset: u32;
		let mut tmp_len: u32;
		let mut tim_ielen: u32;
		let mut tim_ie_offset: u32;
		let mut remainder_ielen: u32;

		tim_bitmap_le = cpu_to_le16(pstapriv.tim_bitmap);

		p = rtw_get_ie(
			pie.offset(_FIXED_IE_LENGTH_ as isize),
			_TIM_IE_ as u8,
			&mut tim_ielen,
			(pnetwork_mlmeext.IELength - _FIXED_IE_LENGTH_) as u32,
		);
		if p != ptr::null_mut() && tim_ielen > 0 {
			tim_ielen += 2;

			premainder_ie = p.offset(tim_ielen as isize);

			tim_ie_offset = (p as usize - pie as usize) as u32;

			remainder_ielen = pnetwork_mlmeext.IELength - tim_ie_offset - tim_ielen;

			//append TIM IE from dst_ie offset
			dst_ie = p;
		} else {
			tim_ielen = 0;

			//calucate head_len
			offset = _FIXED_IE_LENGTH_;

			/* get ssid_ie len */
			p = rtw_get_ie(
				pie.offset(_BEACON_IE_OFFSET_ as isize),
				_SSID_IE_ as u8,
				&mut tmp_len,
				(pnetwork_mlmeext.IELength - _BEACON_IE_OFFSET_) as u32,
			);
			if p != ptr::null_mut() {
				offset += tmp_len + 2;
			}
			// get supported rates len
			p = rtw_get_ie(
				pie.offset(_BEACON_IE_OFFSET_ as isize),
				_SUPPORTEDRATES_IE_ as u8,
				&mut tmp_len,
				(pnetwork_mlmeext.IELength - _BEACON_IE_OFFSET_) as u32,
			);
			if p != ptr::null_mut() {
				offset += tmp_len + 2;
			}
			//DS Parameter Set IE, len=3
			offset += 3;

			premainder_ie = pie.offset(offset as isize);

			remainder_ielen = pnetwork_mlmeext.IELength - offset;

			//append TIM IE from offset
			dst_ie = pie.offset(offset as isize);
		}

		if remainder_ielen > 0 {
			pbackup_remainder_ie = rtw_malloc(remainder_ielen);
			if pbackup_remainder_ie == ptr::null_mut() {
				DBG_871X("%s: pbackup_remainder_ie==NULL\n", __FUNCTION__);
				return;
			}
			_rtw_memcpy(pbackup_remainder_ie, premainder_ie, remainder_ielen);
		}
		*dst_ie = _TIM_IE_;

		if (pstapriv.tim_bitmap & 0xff00) != 0 && (pstapriv.tim_bitmap & 0x00fe) != 0 {
			tim_ielen = 5;
		} else {
			tim_ielen = 4;
		}
		dst_ie = dst_ie.offset(1);
		*dst_ie = tim_ielen as u8;

		if (pstapriv.tim_bitmap & BIT(0)) != 0 {
			//for bc/mc frames
			*dst_ie = BIT(0); //bitmap ctrl
		} else {
			*dst_ie = 0;
		}
		if tim_ielen == 4 {
			let mut pvb: u8 = 0;
			if (pstapriv.tim_bitmap & 0x00fe) != 0 {
				pvb = tim_bitmap_le as u8;
			} else if (pstapriv.tim_bitmap & 0xff00) != 0 {
				pvb = (tim_bitmap_le >> 8) as u8;
			} else {
				pvb = tim_bitmap_le as u8;
			}
			*dst_ie = pvb;
		} else if tim_ielen == 5 {
			_rtw_memcpy(dst_ie as *mut u8, &tim_bitmap_le as *const u16 as *const u8, 2);
			dst_ie = dst_ie.offset(2);
		}

		//copy remainder IE
		if remainder_ielen > 0 {
			_rtw_memcpy(dst_ie, pbackup_remainder_ie, remainder_ielen);
			rtw_mfree(pbackup_remainder_ie, remainder_ielen);
		}

		offset = (dst_ie as usize - pie as usize) as u32;
		pnetwork_mlmeext.IELength = offset + remainder_ielen;
	}

if CONFIG_INTERRUPT_BASED_TXBCN == 0 {
		#[cfg(any(
			all(target_os = "linux", feature = "usb"),
			all(target_os = "linux", feature = "sdio"),
			all(target_os = "linux", feature = "gspi")
		))]
		{
			set_tx_beacon_cmd(padapter);
		}
	}
}

pub fn rtw_add_bcn_ie(padapter: &mut Adapter, pnetwork: &mut WLAN_BSSID_EX, index: u8, data: &[u8], len: u8) {
	let mut pIE: PNDIS_802_11_VARIABLE_IEs;
	let mut bmatch = false;
	let mut pie = pnetwork.IEs.as_mut_ptr();
	let mut p: *mut u8 = ptr::null_mut();
	let mut dst_ie: *mut u8 = ptr::null_mut();
	let mut premainder_ie: *mut u8 = ptr::null_mut();
	let mut pbackup_remainder_ie: *mut u8 = ptr::null_mut();
	let mut i: u32 = 0;
	let mut offset: u32 = 0;
	let mut ielen: u32 = 0;
	let mut ie_offset: u32 = 0;
	let mut remainder_ielen: u32 = 0;

	for i in 0..pnetwork.IELength {
		pIE = (pnetwork.IEs.as_mut_ptr() as usize + i) as PNDIS_802_11_VARIABLE_IEs;

		if pIE.ElementID > index {
			break;
		} else if pIE.ElementID == index {
			// already exist the same IE
			p = pIE as *mut u8;
			ielen = pIE.Length;
			bmatch = true;
			break;
		}

		p = pIE as *mut u8;
		ielen = pIE.Length;
		i += (pIE.Length + 2) as u32;
	}

	if p != ptr::null_mut() && ielen > 0 {
		ielen += 2;

		premainder_ie = p.offset(ielen as isize);

		ie_offset = (p as usize - pie as usize) as u32;

		remainder_ielen = pnetwork.IELength - ie_offset - ielen;

		if bmatch {
			dst_ie = p;
		} else {
			dst_ie = p.offset(ielen as isize);
		}
	}

	if remainder_ielen > 0 {
		pbackup_remainder_ie = rtw_malloc(remainder_ielen);
		if !pbackup_remainder_ie.is_null() && !premainder_ie.is_null() {
			_rtw_memcpy(pbackup_remainder_ie, premainder_ie, remainder_ielen);
		}
	}

	*dst_ie = index;
	dst_ie = dst_ie.offset(1);
	*dst_ie = len;

	if pbackup_remainder_ie != ptr::null_mut() {
		_rtw_memcpy(dst_ie, pbackup_remainder_ie, remainder_ielen);

		rtw_mfree(pbackup_remainder_ie, remainder_ielen);
	}

	offset = (dst_ie as usize - pie as usize) as u32;
	pnetwork.IELength = offset + remainder_ielen;
}

pub fn rtw_remove_bcn_ie(padapter: &mut Adapter, pnetwork: &mut WLAN_BSSID_EX, index: u8) {
	let mut p: *mut u8 = ptr::null_mut();
	let mut dst_ie: *mut u8 = ptr::null_mut();
	let mut premainder_ie: *mut u8 = ptr::null_mut();
	let mut pbackup_remainder_ie: *mut u8 = ptr::null_mut();
	let mut offset: u32 = 0;
	let mut ielen: u32 = 0;
	let mut ie_offset: u32 = 0;
	let mut remainder_ielen: u32 = 0;
	let mut pie = pnetwork.IEs.as_mut_ptr();

	p = rtw_get_ie(pie.offset(_FIXED_IE_LENGTH_ as isize), index, &mut ielen, pnetwork.IELength - _FIXED_IE_LENGTH_);
	if !p.is_null() && ielen > 0 {
		ielen += 2;

		premainder_ie = p.offset(ielen as isize);

		ie_offset = (p as usize - pie as usize) as u32;

		remainder_ielen = pnetwork.IELength - ie_offset - ielen;

		dst_ie = p;
	}

	if remainder_ielen > 0 {
		pbackup_remainder_ie = rtw_malloc(remainder_ielen);
		if !pbackup_remainder_ie.is_null() && !premainder_ie.is_null() {
			_rtw_memcpy(pbackup_remainder_ie, premainder_ie, remainder_ielen);
		}
	}

	//copy remainder IE
	if !pbackup_remainder_ie.is_null() {
		_rtw_memcpy(dst_ie, pbackup_remainder_ie, remainder_ielen);

		rtw_mfree(pbackup_remainder_ie, remainder_ielen);
	}

	offset = (dst_ie as usize - pie as usize) as u32;
	pnetwork.IELength = offset + remainder_ielen;
}

pub fn chk_sta_is_alive(psta: &mut sta_info) -> u8 {
	let mut ret: u8 = _FALSE;

	//if(sta_last_rx_pkts(psta) == sta_rx_pkts(psta))
	if (psta.sta_stats.last_rx_data_pkts + psta.sta_stats.last_rx_ctrl_pkts) == (psta.sta_stats.rx_data_pkts + psta.sta_stats.rx_ctrl_pkts) {
	#[cfg(not(feature = "CONFIG_LPS"))]
	{
		ret = _TRUE;
	}

	sta_update_last_rx_pkts(psta);

	ret
}

pub fn rtw_ap_expire_timeout_chk(padapter: &mut Adapter) {
		let mut psta: *mut sta_info = ptr::null_mut();
		let mut phead: *mut list_head = ptr::null_mut();
		let mut plist: *mut list_head = ptr::null_mut();
		let mut pstapriv = &mut padapter.stapriv;
		let mut pmlmepriv = &mut padapter.mlmepriv;
		let mut updated: u8 = _FALSE;
		let mut i: i32 = 0;
		let mut chk_alive_list: [u8; NUM_STA] = [0; NUM_STA];
		let mut chk_alive_num: i32 = 0;

		if check_fwstate(pmlmepriv, WIFI_AP_STATE) == _FALSE {
			return;
		}

		_enter_critical_bh(&mut pstapriv.asoc_list_lock, &mut irqL);

		phead = &mut pstapriv.asoc_list;
		plist = get_next(phead);
		#[cfg(DBG_EXPIRATION_CHK)]
		{
			if rtw_end_of_queue_search(phead, plist) == _TRUE {
				DBG_871X("asoc_list empty\n");
			} else {
				DBG_871X("asoc_list len = %d\n", pstapriv.asoc_list_cnt);}
		}
	}

	while rtw_end_of_queue_search(phead, plist) == _FALSE {
		psta = container_of!(plist, sta_info, auth_list);
		plist = get_next(plist);

		if psta.expire_to > 0 {
			psta.expire_to -= 1;
			if psta.expire_to == 0 {
				rtw_list_delete(&psta.auth_list);
				pstapriv.auth_list_cnt -= 1;

				DBG_871X("auth expire %02X%02X%02X%02X%02X%02X\n",
					psta.hwaddr[0],psta.hwaddr[1],psta.hwaddr[2],psta.hwaddr[3],psta.hwaddr[4],psta.hwaddr[5]);

				_exit_critical_bh(&mut pstapriv.auth_list_lock, &mut irqL);

				_enter_critical_bh(&mut pstapriv.sta_hash_lock, &mut irqL);
				rtw_free_stainfo(padapter, psta);
				_exit_critical_bh(&mut pstapriv.sta_hash_lock, &mut irqL);

				_enter_critical_bh(&mut pstapriv.auth_list_lock, &mut irqL);
			}
		}
	}

	_exit_critical_bh(&mut pstapriv.asoc_list_lock, &mut irqL);

	psta = ptr::null_mut();

	_enter_critical_bh(&mut pstapriv.asoc_list_lock, &mut irqL);

	phead = &mut pstapriv.asoc_list;
	plist = get_next(phead);

#[cfg(DBG_EXPIRATION_CHK)]{
	if rtw_end_of_queue_search(phead, plist) == _TRUE {
		DBG_871X("asoc_list empty\n");
	} else {
		DBG_871X("asoc_list len = %d\n", pstapriv.asoc_list_cnt);
	}
}
	psta = container_of!(plist, sta_info, asoc_list);
	plist = get_next(plist);

	#[cfg(feature = "CONFIG_AUTO_AP_MODE")]
	{
		if psta.isrc {
			continue;
		}
	}

	


	if chk_sta_is_alive(psta) == _TRUE || psta.expire_to == 0 {
		psta.expire_to = pstapriv.expire_to;
		psta.keep_alive_trycnt = 0;
		#[cfg(feature = "CONFIG_TX_MCAST2UNI")]
		{
			psta.under_exist_checking = 0;
		}
	} else {
		psta.expire_to -= 1;
	}

#[cfg(not (feature = "CONFIG_ACTIVE_KEEP_ALIVE_CHECK"))]
{
	#[cfg(feature = "CONFIG_TX_MCAST2UNI")]
	{
		#[cfg(feature = "CONFIG_80211N_HT")]
		{
			if (psta.flags & WLAN_STA_HT) != 0 && (psta.htpriv.agg_enable_bitmap != 0 || psta.under_exist_checking != 0) {
				// check sta by delba(addba) for 11n STA
				if psta.expire_to <= (pstapriv.expire_to - 50) {
					DBG_871X("asoc expire by DELBA/ADDBA! (%d s)", (pstapriv.expire_to - psta.expire_to) * 2);
					psta.under_exist_checking = 0;
					psta.expire_to = 0;
				} else if psta.expire_to <= (pstapriv.expire_to - 3) && psta.under_exist_checking == 0 {
					DBG_871X("asoc check by DELBA/ADDBA! (%d s)", (pstapriv.expire_to - psta.expire_to) * 2);
					psta.under_exist_checking = 1;
					//tear down TX AMPDU
					send_delba(padapter, 1, psta.hwaddr);
					psta.htpriv.agg_enable_bitmap = 0x0;
					psta.htpriv.candidate_tid_bitmap = 0x0;
				}
			}
		}
	}
}
if psta.expire_to <= 0 {
	#[cfg(feature = "CONFIG_ACTIVE_KEEP_ALIVE_CHECK")]{
		if padapter.registrypriv.wifi_spec == 1 {
			psta.expire_to = pstapriv.expire_to;
			continue;
		}
		if (psta.state & WIFI_SLEEP_STATE) != 0 && (psta.state & WIFI_STA_ALIVE_CHK_STATE) == 0 {
			psta.expire_to = pstapriv.expire_to;
			psta.state |= WIFI_STA_ALIVE_CHK_STATE;
			pstapriv.tim_bitmap |= BIT(psta.aid);
			update_beacon(padapter, _TIM_IE_, None, _FALSE);
			if !padapter.mlmeextpriv.active_keep_alive_check {
				continue;
			}
		}
	}

rtw_list_delete(&psta.asoc_list);
pstapriv.asoc_list_cnt -= 1;
DBG_871X(r#"asoc expire "MAC_FMT", state=0x%x"#, MAC_ARG(psta.hwaddr), psta.state);
updated = ap_free_sta(padapter, psta, _FALSE, WLAN_REASON_DEAUTH_LEAVING);
} else {
	if psta.sleepq_len > (NR_XMITFRAME / pstapriv.asoc_list_cnt) && padapter.xmitpriv.free_xmitframe_cnt < ((NR_XMITFRAME / pstapriv.asoc_list_cnt) / 2) {
		DBG_871X(r#"%s sta:"MAC_FMT", sleepq_len:%u, free_xmitframe_cnt:%u, asoc_list_cnt:%u, clear sleep_q"#, __func__, MAC_ARG(psta.hwaddr), psta.sleepq_len, padapter.xmitpriv.free_xmitframe_cnt, pstapriv.asoc_list_cnt);
		wakeup_sta_to_xmit(padapter, psta);
	}
}
_exit_critical_bh(&mut pstapriv.asoc_list_lock, &mut irqL);
#[cfg(feature = "CONFIG_ACTIVE_KEEP_ALIVE_CHECK")]
{
	if chk_alive_num {
		let backup_oper_channel = 0;
		let pmlmeext = &padapter.mlmeextpriv;
		/* switch to correct channel of current network  before issue keep-alive frames */
		if rtw_get_oper_ch(padapter) != pmlmeext.cur_channel {
			backup_oper_channel = rtw_get_oper_ch(padapter);
			SelectChannel(padapter, pmlmeext.cur_channel);
		}
	}

/*
issue null data to check sta alive.
*/


	for chk_alive_num in 0..chk_alive_num {
		let psta = rtw_get_stainfo_by_offset(pstapriv, chk_alive_list[chk_alive_num]);
		if (psta.state & _FW_LINKED) == 0 {
			continue;
		}
		let ret = if (psta.state & WIFI_SLEEP_STATE) != 0 {
			issue_nulldata(padapter, psta.hwaddr, 0, 1, 50)
		} else {
			issue_nulldata(padapter, psta.hwaddr, 0, 3, 50)
		};
		psta.keep_alive_trycnt += 1;
		if ret == _SUCCESS {
			DBG_871X(r#"asoc check, sta("MAC_FMT") is alive"#, MAC_ARG(psta.hwaddr));
			psta.expire_to = pstapriv.expire_to;
			psta.keep_alive_trycnt = 0;
			continue;
		} else if psta.keep_alive_trycnt <= 3 {
			DBG_871X(r#"ack check for asoc expire, keep_alive_trycnt=%d"#, psta.keep_alive_trycnt);
			psta.expire_to = 1;
			continue;
		}
		psta.keep_alive_trycnt = 0;
		DBG_871X(r#"asoc expire "MAC_FMT", state=0x%x"#, MAC_ARG(psta.hwaddr), psta.state);
		_enter_critical_bh(&mut pstapriv.asoc_list_lock, &mut irqL);
		if !rtw_is_list_empty(&psta.asoc_list) {
			rtw_list_delete(&psta.asoc_list);
			pstapriv.asoc_list_cnt -= 1;
			updated = ap_free_sta(padapter, psta, _FALSE, WLAN_REASON_DEAUTH_LEAVING);
		}
		_exit_critical_bh(&mut pstapriv.asoc_list_lock, &mut irqL);
	}
	if backup_oper_channel == 0 {
    return;
} else {
		SelectChannel(padapter, backup_oper_channel);
}
}
associated_clients_update(padapter, updated);
}

pub fn add_RATid(padapter: &mut Adapter, psta: &mut StaInfo, rssi_level: u8) {
	let mut i = 0;
	let rf_type = 0;
	let init_rate = 0;
	let sta_band = 0;
	let raid = 0;
	let shortGIrate = false;
	let limit = 0;
	let mut tx_ra_bitmap = 0;
	let psta_ht = &mut psta.htpriv;
	let pmlmepriv = &padapter.mlmepriv;
	let pcur_network = &pmlmepriv.cur_network.network;

	#[cfg(feature = "CONFIG_80211N_HT")]{
	if !psta {
		return;
	}

	if (psta.state & _FW_LINKED) == 0 {
		return;
	}
	// b/g mode ra_bitmap
	for i in 0..psta.bssrateset.len() {
		if psta.bssrateset[i] != 0 {
			tx_ra_bitmap |= rtw_get_bit_value_from_ieee_value(psta.bssrateset[i] & 0x7f);
		}
	}
}
#[cfg(feature = "CONFIG_80211N_HT")]{
	#[cfg(feature = "CONFIG_80211AC_VHT")]{
	if psta.vhtpriv.vht_option {
		let mut vht_bitmap = 0;
		vht_bitmap = rtw_vht_rate_to_bitmap(psta.vhtpriv.vht_mcs_map);
		tx_ra_bitmap |= (vht_bitmap << 12);
		shortGIrate = psta.vhtpriv.sgi;
	}
	}
	if #[cfg(not feature = "CONFIG_80211AC_VHT")] && psta_ht.ht_option {		
			let rf_type = rtw_hal_get_hwreg(padapter, HW_VAR_RF_TYPE);
			if rf_type == RF_2T2R {
				limit = 16; // 2R
			} else {
				limit = 8; //  1R
			}
			for i in 0..limit {
				if psta_ht.ht_cap.supp_mcs_set[i / 8] & BIT(i % 8) {
					tx_ra_bitmap |= BIT(i + 12);
				}
			}
			shortGIrate = psta_ht.sgi;
	

	}
}
if pcur_network.Contiguration.DSConfig > 14 {
	#[cfg(feature = "CONFIG_80211AC_VHT")]{
		if psta.vhtpriv.vht_option {
			sta_band = WIRELESS_11_5AC;	
	}
}
if !psta.vhtpriv.vht_option {
	if tx_ra_bitmap & 0xffff000 {
		sta_band |= WIRELESS_11_5N | WIRELESS_11A;
	} else {
		sta_band = WIRELESS_11A;
	}
}
if tx_ra_bitmap & 0xffff000 {
	sta_band |= WIRELESS_11_24N | WIRELESS_11G | WIRELESS_11B;
} else 		if tx_ra_bitmap & 0xff0 {
	sta_band |= WIRELESS_11G | WIRELESS_11B;
} else {
	sta_band = WIRELESS_11B;
}
psta.wireless_mode = sta_band;
raid = rtw_hal_networktype_to_raid(padapter, sta_band);

init_rate = get_highest_rate_idx(tx_ra_bitmap) & 0x3f;

if psta.aid < NUM_STA {
	arg[4] = u8 {0};
	arg[0] = psta.mac_id;
	arg[1] = raid;
	arg[2] = shortGIrate;
	arg[3] = init_rate;

	DBG_871X("%s=> mac_id:%d , raid:%d , shortGIrate =%d, bitmap=0x%x\n", __FUNCTION__, psta.mac_id, raid, shortGIrate, tx_ra_bitmap);
	rtw_hal_add_ra_tid(padapter, tx_ra_bitmap, arg, rssi_level);

	if shortGIrate == true {
		init_rate |= BIT(6);
		psta.raid = raid;
		psta.init_rate = init_rate;
	}
}
else {
	DBG_871x("station aid %d exceed the max number\n", psta.aid);
}
}
}

fn update_bmc_sta(padapter: &mut _adapter) {
	let mut irqL: irqL;
	let mut init_rate: u32 = 0;
	let mut network_type: u8;
	let mut raid: u8;
	let mut i: i32;
	let mut supportRateNum: i32 = 0;
	let mut tx_ra_bitmap: u32 = 0;
	let pmlmepriv: &mut mlme_priv = &mut padapter.mlmepriv;
	let pmlmeext: &mut mlme_ext_priv = &mut padapter.mlmeextpriv;
	let pmlmeinfo: &mut mlme_ext_info = &mut pmlmeext.mlmext_info;
	let pcur_network: &mut WLAN_BSSID_EX = &mut pmlmepriv.cur_network.network;
	let psta: &mut sta_info = rtw_get_bcmc_stainfo(padapter);

	if psta {
		psta.aid = 0; // default set to 0
		// psta->mac_id = psta->aid+4;
		psta.mac_id = psta.aid + 1; // mac_id=1 for bc/mc stainfo

		pmlmeinfo.FW_sta_info[psta.mac_id].psta = psta;

		psta.qos_option = 0;
		#[cfg(CONFIG_80211N_HT)]
		{
			psta.htpriv.ht_option = false;
		}
		psta.ieee8021x_blocked = 0;

		_rtw_memset((psta.sta_stats as *mut u8), 0, size_of::<stainfo_stats>());

		//prepare for add_RATid
		supportRateNum = rtw_get_rateset_len(pcur_network.SupportedRates.as_mut_ptr());
		network_type = rtw_check_network_type(
			pcur_network.SupportedRates.as_mut_ptr(),
			supportRateNum,
			1,
		);

		__rtw_memcpy(psta.bssrateset.as_mut_ptr(), &pcur_network.SupportedRates, supportRateNum);
		psta.bssratelen = supportRateNum;

		//b/g mode ra_bitmap
		i = 0;
		while i < supportRateNum {
			if psta.bssrateset[i] != 0 {
				tx_ra_bitmap |= rtw_get_bit_value_from_ieee_value(psta.bssrateset[i] & 0x7f);
			}
			i += 1;
		}
		if pcur_network.Configuration.DSConfig > 14 {
			//force to A mode. 5G doesn't support CCK rates
			network_type = WIRELESS_11A;
			tx_ra_bitmap = 0x150; //6, 12, 24 Mbps
		} else {
			//force to b mode
			network_type = WIRELESS_11B;
			tx_ra_bitmap = 0xf;
		}

		raid = rtw_hal_networktype_to_raid(padapter, network_type);

		init_rate = get_highest_rate_idx(tx_ra_bitmap & 0x0fffffff) & 0x3f;

		rtw_hal_set_odm_var(padapter, HAL_ODM_STA_INFO, psta, _TRUE);
		if pHalData.fw_ractrl == _TRUE {
			let mut arg: [u8; 4] = [0; 4];

			arg[0] = psta.mac_id;
			arg[1] = raid;
			arg[2] = 0;
			arg[3] = init_rate;

			DBG_871X("%s=> mac_id:%d , raid:%d , bitmap=0x%x\n",
					 __FUNCTION__, psta.mac_id, raid, tx_ra_bitmap);

			rtw_hal_add_ra_tid(padapter, tx_ra_bitmap, &mut arg, 0);
	}
	//set ra_id, init_rate
	psta.raid = raid;
	psta.init_rate = init_rate;

	rtw_stassoc_hw_rpt(padapter, psta);

	_enter_critical_bh(&psta.lock, &irqL);
	psta.state = _FW_LINKED;
	_exit_critical_bh(&psta.lock, &irqL);
	} else {
		DBG_871X("add_RATid_bmc_sta error!\n");
	}
}

fn update_sta_info_apmode(padapter: &mut _adapter) {
	let _irqL: irqL;
	let pmlmepriv: &mut mlme_priv = &mut padapter.mlmepriv;
	let psecuritypriv: &mut security_priv = &mut padapter.securitypriv;
	let pmlmeext: &mut mlme_ext_priv = &mut padapter.mlmeextpriv;
	#[cfg(CONFIG_80211N_HT)]{
	let phtpriv_ap: &mut ht_priv = &mut pmlmepriv.htpriv;
	let phtpriv_sta: &mut ht_priv = &mut psta.htpriv;
	}
	DBG_871X("%s\n", __FUNCTION__);

	//ap mode
	rtw_hal_set_odm_var(padapter, HAL_ODM_STA_INFO, psta, true);

	if psecuritypriv.dot11AuthAlgrthm == dot11AuthAlgrthm_8021X {
		psta.ieee8021x_blocked = true;
		psta.dot118021XPrivacy = psecuritypriv.dot11PrivacyAlgrthm;
	} else {
		psta.ieee8021x_blocked = false;
	}
	VCS_update(padapter, psta);
	#[cfg(CONFIG_80211N_HT)]{
		if phtpriv_sta.ht_option {
			//check if sta supports rx ampdu
			phtpriv_sta.ampdu_enable = phtpriv_ap.ampdu_enable;

			//check if sta supports s Short GI
			if phtpriv_sta.ht_cap.cap_info & phtpriv_ap.ht_cap.cap_info & IEEE80211_HT_CAP_SGI_20 {
				phtpriv_sta.sgi = true;
			}
			if phtpriv_sta.ht_cap.cap_info & phtpriv_ap.ht_cap.cap_info & IEEE80211_HT_CAP_SGI_40 {
				phtpriv_sta.sgi = true;
				
			}
			// bwmode
			if phtpriv_sta.ht_cap.cap_info & phtpriv_ap.ht_cap.cap_info & IEEE80211_HT_CAP_SUP_WIDTH {
			phtpriv_sta.bwmode = pmlmeext.cur_bwmode;
			phtpriv_sta.ch_offset = pmlmeext.cur_ch_offset;
		}
		psta.qos_option = true;
		}
		else {
			phtpriv_sta.ampdu_enable = false;
			phtpriv_sta.sgi = false;
			phtpriv_sta.bwmode = CHANNEL_WIDTH_20;
			phtpriv_sta.ch_offset = HAL_PRIME_CHNL_OFFSET_DONT_CARE;
		}
		//Rx AMPDU
		send_delba(padapter, 0, psta.hwaddr);// recipient

		//TX AMPDU
		send_delba(padapter, 1, psta.hwaddr);   // originator
		phtpriv_sta.agg_enable_bitmap = 0x0;    // reset
		phtpriv_sta.candidate_tid_bitmap = 0x0; // reset
}
#[cfg(CONFIG_80211AC_VHT)]{
	update_sta_vht_info_apmode(padapter, psta);
}

//todo: init other variables
psta.sta_stats = stainfo_stats::default();

enter_critical_bh(&psta.lock, &irqL);
psta.state = FW_LINKED;
exit_critical_bh(&psta.lock, &irqL);

}

fn update_hw_ht_param(padapter: &mut _adapter) {
	let max_AMPDU_len: u8;
	let min_MPDU_spacing: u8;
	let pregpriv: &mut registry_priv = &mut padapter.registrypriv;
	let pmlmeext: &mut mlme_ext_priv = &mut padapter.mlmeextpriv;
	let pmlmeinfo: &mut mlme_ext_info = &mut pmlmeext.mlmext_info;

	DBG_871X("%s\n", FUNCTION);

	max_AMPDU_len = pmlmeinfo.HT_caps.u.HT_cap_element.ampdu_params_info & 0x03;

	min_MPDU_spacing = (pmlmeinfo.HT_caps.u.HT_cap_element.ampdu_params_info & 0x1c) >> 2;

	rtw_hal_set_hwreg(padapter, HW_VAR_AMPDU_MIN_SPACE, &min_MPDU_spacing);

	rtw_hal_set_hwreg(padapter, HW_VAR_AMPDU_FACTOR, &max_AMPDU_len);

	//Config SM Power Save setting

	pmlmeinfo.SM_PS = (pmlmeinfo.HT_caps.u.HT_cap_element.HT_caps_info & 0x0C) >> 2;

	if pmlmeinfo.SM_PS == WLAN_HT_CAP_SM_PS_STATIC {
		DBG_871X("%s(): WLAN_HT_CAP_SM_PS_STATIC\n", FUNCTION);
	}
}
