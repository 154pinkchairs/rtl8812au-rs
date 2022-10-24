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
use core::ptr::write_volatile;
use core::ptr::read_volatile;
use core::slice::from_raw_parts;
use core::slice::from_raw_parts_mut;


if CONFIG_AP_MODE {
	pub static mut RTW_WPA_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x01];
	pub static mut WMM_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x02];
	pub static mut WPS_OUI: [u8; 4] = [0x00, 0x50, 0xf2, 0x04];
	pub static mut P2P_OUI: [u8; 4] = [0x50, 0x6f, 0x9a, 0x09];
	pub static mut WFD_OUI: [u8; 4] = [0x50, 0x6f, 0x9a, 0x0a];
}

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
		//append TIM IE
		*dst_ie++ = _TIM_IE_;

		if tim_ielen == 4 {
			*dst_ie++ = 3;
			*dst_ie++ = 0;
			*dst_ie++ = 1;
			*dst_ie++ = (u8)tim_bitmap_le;
		} else if tim_ielen == 5 {
			*dst_ie++ = 4;
			*dst_ie++ = 0;
			*dst_ie++ = 1;
			_rtw_memcpy(dst_ie, &tim_bitmap_le, 2);
			dst_ie = dst_ie.offset(2);
		}

		if pstapriv.tim_bitmap & BIT(0) {
			//bc/mc packets
			*dst_ie++ = pstapriv.tim_bitmap >> 1;
		} else {
			//bc/mc packets
			*dst_ie++ = pstapriv.tim_bitmap >> 0;
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
		#if 0
		if(psta->state&WIFI_SLEEP_STATE)
			ret = _TRUE;
		#endif
	} else {
		ret = _TRUE;
	}

	sta_update_last_rx_pkts(psta);

	ret
}

void rtw_ap_expire_timeout_chk(_adapter *padapter)
{
	struct sta_info *psta;
	_irqL irqL;
	_list	*phead, *plist;
	struct sta_priv *pstapriv = &padapter->stapriv;
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	u8 updated = _FALSE;
	int i;
	u8 chk_alive_list[NUM_STA];
	int chk_alive_num = 0;

	if (check_fwstate(pmlmepriv, WIFI_AP_STATE) == _FALSE)
		return;

	_enter_critical_bh(&pstapriv->asoc_list_lock, &irqL);

	phead = &pstapriv->asoc_list;
	plist = get_next(phead);

	/* check asoc_queue */
	while ((rtw_end_of_queue_search(phead, plist)) == _FALSE)
	{
		psta = LIST_CONTAINOR(plist, struct sta_info, asoc_list);

		plist = get_next(plist);

		if (psta->expire_to > 0)
		{
			psta->expire_to--;
			if (psta->expire_to > 0)
				continue;
		}

		rtw_list_delete(&psta->asoc_list);
		pstapriv->asoc_list_cnt--;

		DBG_871X("asoc expire "MAC_FMT", state=0x%x\n", MAC_ARG(psta->hwaddr), psta->state);
		updated = ap_free_sta(padapter, psta, _FALSE, WLAN_REASON_DEAUTH_LEAVING);

	}
	else {
		if (psta->sleepq_len > 0) {
			if (padapter->xmitpriv.free_xmitframe_cnt > (NR_XMITFRAME/pstapriv->asoc_list_cnt) &&
				pstapriv->asoc_list_cnt < (NUM_STA - 4)
			){
				DBG_871X("%s sta:"MAC_FMT", sleepq_len:%u, free_xmitframe_cnt:%u, asoc_list_cnt:%u, clear sleep_q\n", __func__
					, MAC_ARG(psta->hwaddr)
					, psta->sleepq_len, padapter->xmitpriv.free_xmitframe_cnt, pstapriv->asoc_list_cnt);
				wakeup_sta_to_xmit(padapter, psta);
			}
		}
	}

	_exit_critical_bh(&pstapriv->asoc_list_lock, &irqL);

	associated_clients_update(padapter, updated);
}
#[cfg(CONFIG_ACTIVE_KEEP_ALIVE_CHECK)]
if chk_alive_num {
	backup_oper_channel = rtw_get_oper_ch(padapter);
	if (backup_oper_channel != pmlmeext->cur_channel) {
		SelectChannel(padapter, pmlmeext->cur_channel);
	}

	/* issue null data to check sta alive*/
	for (i = 0; i < chk_alive_num; i++) {
		
		int ret = _FAIL;

		psta = rtw_get_stainfo_by_offset(pstapriv, chk_alive_list[i]);
		if(!(psta->state &_FW_LINKED))
			continue;		
	
		if (psta->state & WIFI_SLEEP_STATE)
			ret = issue_nulldata(padapter, psta->hwaddr, 0, 1, 50);
		else
			ret = issue_nulldata(padapter, psta->hwaddr, 0, 3, 50);

		psta->keep_alive_trycnt++;
		if (ret == _SUCCESS)
		{
			DBG_871X("asoc check, sta(" MAC_FMT ") is alive\n", MAC_ARG(psta->hwaddr));
			psta->expire_to = pstapriv->expire_to;
			psta->keep_alive_trycnt = 0;
			continue;
		}
		else if (psta->keep_alive_trycnt < 3)
		{
			DBG_871X("ack check for asoc expire, keep_alive_trycnt=%d\n", psta->keep_alive_trycnt);
			_enter_critical_bh(&pstapriv->asoc_list_lock, &irqL);
			if (rtw_is_list_empty(&psta->asoc_list)==_FALSE) {
				rtw_list_delete(&psta->asoc_list);
				pstapriv->asoc_list_cnt--;
				updated = ap_free_sta(padapter, psta, _FALSE, WLAN_REASON_DEAUTH_LEAVING);
			}
			_exit_critical_bh(&pstapriv->asoc_list_lock, &irqL);

			associated_clients_update(padapter, updated);
		}

		if backup_oper_channel > 0 /* back to the original operation channel */
			SelectChannel(padapter, backup_oper_channel);
	associated_clients_update(padapter, updated);
}

pub fn add_RATid(padapter &mut Adapter, psta &mut StaInfo, rssi_level u8) -> Result {
	