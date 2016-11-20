/**
 *
 * \section COPYRIGHT
 *
 * Copyright 2013-2015 Software Radio Systems Limited
 *
 * \section LICENSE
 *
 * This file is part of the srsLTE library.
 *
 * srsLTE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsLTE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srslte/enb/enb_ul.h"

#include <complex.h>
#include <math.h>
#include <string.h>


#define CURRENT_FFTSIZE   srslte_symbol_sz(q->cell.nof_prb)
#define CURRENT_SFLEN     SRSLTE_SF_LEN(CURRENT_FFTSIZE)

#define CURRENT_SLOTLEN_RE SRSLTE_SLOT_LEN_RE(q->cell.nof_prb, q->cell.cp)
#define CURRENT_SFLEN_RE SRSLTE_SF_LEN_RE(q->cell.nof_prb, q->cell.cp)

#define MAX_CANDIDATES  16

int srslte_enb_ul_init(srslte_enb_ul_t *q, srslte_cell_t cell, 
                       srslte_prach_cfg_t *prach_cfg, 
                       srslte_refsignal_dmrs_pusch_cfg_t *pusch_cfg, 
                       srslte_pusch_hopping_cfg_t *hopping_cfg, 
                       srslte_pucch_cfg_t *pucch_cfg)
{
  int ret = SRSLTE_ERROR_INVALID_INPUTS; 
  
  if (q                 != NULL &&
      srslte_cell_isvalid(&cell))   
  {
    ret = SRSLTE_ERROR;
    
    bzero(q, sizeof(srslte_enb_ul_t));
    
    q->cell = cell;
    
    if (hopping_cfg) {
      memcpy(&q->hopping_cfg, hopping_cfg, sizeof(srslte_pusch_hopping_cfg_t));
    } 
    
    q->users = calloc(sizeof(srslte_enb_ul_user_t*), SRSLTE_SIRNTI);
    if (!q->users) {
      perror("malloc");
      goto clean_exit;
    }
    
    if (srslte_ofdm_rx_init(&q->fft, q->cell.cp, q->cell.nof_prb)) {
      fprintf(stderr, "Error initiating FFT\n");
      goto clean_exit;
    }
    srslte_ofdm_set_normalize(&q->fft, false);
    srslte_ofdm_set_freq_shift(&q->fft, -0.5);

    if (srslte_pucch_init(&q->pucch, q->cell)) {
      fprintf(stderr, "Error creating PUCCH object\n");
      goto clean_exit;
    }

    if (srslte_pusch_init(&q->pusch, q->cell)) {
      fprintf(stderr, "Error creating PUSCH object\n");
      goto clean_exit;
    }
    
    if (prach_cfg) {
      if (srslte_prach_init_cfg(&q->prach, prach_cfg, q->cell.nof_prb)) {
        fprintf(stderr, "Error initiating PRACH\n");
        goto clean_exit; 
      }
      srslte_prach_set_detect_factor(&q->prach, 60);    
    }
    
    srslte_pucch_set_threshold(&q->pucch, 0.5, 0.5);
    
    if (srslte_chest_ul_init(&q->chest, cell)) {
      fprintf(stderr, "Error initiating channel estimator\n");
      goto clean_exit; 
    }
    
    // Configure common PUCCH configuration 
    srslte_pucch_set_cfg(&q->pucch, pucch_cfg, pusch_cfg->group_hopping_en);
    
    // SRS is a dedicated configuration
    srslte_chest_ul_set_cfg(&q->chest, pusch_cfg, pucch_cfg, NULL);
        
    q->sf_symbols = srslte_vec_malloc(CURRENT_SFLEN_RE * sizeof(cf_t));
    if (!q->sf_symbols) {
      perror("malloc");
      goto clean_exit; 
    }
    
    q->ce = srslte_vec_malloc(CURRENT_SFLEN_RE * sizeof(cf_t));
    if (!q->ce) {
      perror("malloc");
      goto clean_exit; 
    }
        
    ret = SRSLTE_SUCCESS;
    
  } else {
    fprintf(stderr, "Invalid cell properties: Id=%d, Ports=%d, PRBs=%d\n",
            cell.id, cell.nof_ports, cell.nof_prb);      
  }

clean_exit: 
  if (ret == SRSLTE_ERROR) {
    srslte_enb_ul_free(q);
  }
  return ret;
}

void srslte_enb_ul_free(srslte_enb_ul_t *q)
{
  if (q) {
    
    if (q->users) {
      for (int i=0;i<SRSLTE_SIRNTI;i++) {
        if (q->users[i]) {
          free(q->users[i]);
        }
      }
      free(q->users);
    }
    
    srslte_prach_free(&q->prach);
    srslte_ofdm_rx_free(&q->fft);
    srslte_pucch_free(&q->pucch);
    srslte_pusch_free(&q->pusch);
    srslte_chest_ul_free(&q->chest);
    if (q->sf_symbols) {
      free(q->sf_symbols);
    }
    if (q->ce) {
      free(q->ce);
    }
    bzero(q, sizeof(srslte_enb_ul_t));
  }  
}

int srslte_enb_ul_add_rnti(srslte_enb_ul_t *q, uint16_t rnti)
{
  if (!q->users[rnti]) {
    q->users[rnti] = malloc(sizeof(srslte_enb_ul_user_t));
    return srslte_pusch_set_rnti(&q->pusch, rnti);
  } else {
    fprintf(stderr, "Error adding rnti=0x%x, already exists\n", rnti);
    return -1; 
  }
}

void srslte_enb_ul_rem_rnti(srslte_enb_ul_t *q, uint16_t rnti)
{
  if (q->users[rnti]) {
    free(q->users[rnti]); 
    q->users[rnti] = NULL; 
    srslte_pusch_clear_rnti(&q->pusch, rnti);
  }
}

int srslte_enb_ul_cfg_ue(srslte_enb_ul_t *q, uint16_t rnti, 
                         srslte_uci_cfg_t *uci_cfg, 
                         srslte_pucch_sched_t *pucch_sched,
                         srslte_refsignal_srs_cfg_t *srs_cfg) 
{
  if (q->users[rnti]) {
    if (uci_cfg) {
      memcpy(&q->users[rnti]->uci_cfg, uci_cfg, sizeof(srslte_uci_cfg_t));
      q->users[rnti]->uci_cfg_en = true; 
    } else {
      q->users[rnti]->uci_cfg_en = false; 
    }
    if (pucch_sched) {
      memcpy(&q->users[rnti]->pucch_sched, pucch_sched, sizeof(srslte_pucch_sched_t));
    }
    if (srs_cfg) {
      memcpy(&q->users[rnti]->srs_cfg, srs_cfg, sizeof(srslte_refsignal_srs_cfg_t));
      q->users[rnti]->srs_cfg_en = true; 
    } else {
      q->users[rnti]->srs_cfg_en = false; 
    }
    return SRSLTE_SUCCESS;
  } else {
    fprintf(stderr, "Error configuring UE: rnti=0x%x not found\n", rnti);
    return SRSLTE_ERROR; 
  }
}

void srslte_enb_ul_fft(srslte_enb_ul_t *q, cf_t *signal_buffer) 
{
  srslte_ofdm_rx_sf(&q->fft, signal_buffer, q->sf_symbols);
}

int get_pucch(srslte_enb_ul_t *q, uint16_t rnti, 
              uint32_t pdcch_n_cce, uint32_t sf_rx, 
              srslte_uci_data_t *uci_data, uint8_t bits[SRSLTE_PUCCH_MAX_BITS]) 
{
  float noise_power = srslte_chest_ul_get_noise_estimate(&q->chest); 
  
  srslte_pucch_format_t format = srslte_pucch_get_format(uci_data, q->cell.cp);
    
  uint32_t n_pucch = srslte_pucch_get_npucch(pdcch_n_cce, format, uci_data->scheduling_request, &q->users[rnti]->pucch_sched);
  
  if (srslte_chest_ul_estimate_pucch(&q->chest, q->sf_symbols, q->ce, format, n_pucch, sf_rx)) {
    fprintf(stderr,"Error estimating PUCCH DMRS\n");
    return SRSLTE_ERROR;
  }
  
  
  int ret_val = srslte_pucch_decode(&q->pucch, format, n_pucch, sf_rx, q->sf_symbols, q->ce, noise_power, bits); 
  if (ret_val < 0) {
    fprintf(stderr,"Error decoding PUCCH\n");
    return SRSLTE_ERROR; 
  }
  return ret_val;
}

int srslte_enb_ul_get_pucch(srslte_enb_ul_t *q, uint16_t rnti, 
                            uint32_t pdcch_n_cce, uint32_t sf_rx, 
                            srslte_uci_data_t *uci_data)
{
  uint8_t bits[SRSLTE_PUCCH_MAX_BITS];
  
  if (q->users[rnti]) {

    int ret_val = get_pucch(q, rnti, pdcch_n_cce, sf_rx, uci_data, bits);

    // If we are looking for SR and ACK at the same time and ret=0, means there is no SR. 
    // try again to decode ACK only 
    if (uci_data->scheduling_request && uci_data->uci_ack_len && ret_val != 1) {
      uci_data->scheduling_request = false; 
      ret_val = get_pucch(q, rnti, pdcch_n_cce, sf_rx, uci_data, bits);
    }

    // update schedulign request 
    if (uci_data->scheduling_request) {
      uci_data->scheduling_request = (ret_val==1); 
    }
    
    // Save ACK bits 
    if (uci_data->uci_ack_len > 0) {
      if (ret_val > 0) {
        uci_data->uci_ack = bits[0];      
      } else {
        uci_data->uci_ack = 0; 
      }
    }
    return SRSLTE_SUCCESS;
  } else {
    fprintf(stderr, "Error getting PUCCH: rnti=0x%x not found\n", rnti);
    return SRSLTE_ERROR; 
  }
}

int srslte_enb_ul_get_pusch(srslte_enb_ul_t *q, srslte_ra_ul_grant_t *grant, srslte_softbuffer_rx_t *softbuffer, 
                            uint16_t rnti, uint32_t rv_idx, uint32_t current_tx_nb, 
                            uint8_t *data, srslte_uci_data_t *uci_data, uint32_t tti)
{
  if (q->users[rnti]) {
    if (srslte_pusch_cfg(&q->pusch, 
                        &q->pusch_cfg, 
                        grant, 
                        q->users[rnti]->uci_cfg_en?&q->users[rnti]->uci_cfg:NULL, 
                        &q->hopping_cfg, 
                        q->users[rnti]->srs_cfg_en?&q->users[rnti]->srs_cfg:NULL, 
                        tti, rv_idx, current_tx_nb)) {
      fprintf(stderr, "Error configuring PDSCH\n");
      return SRSLTE_ERROR;
    }
  } else {
      if (srslte_pusch_cfg(&q->pusch, 
                        &q->pusch_cfg, 
                        grant, 
                        NULL, 
                        &q->hopping_cfg, 
                        NULL, 
                        tti, rv_idx, current_tx_nb)) {
      fprintf(stderr, "Error configuring PDSCH\n");
      return SRSLTE_ERROR;
    }
  }
  
  uint32_t cyclic_shift_for_dmrs = 0; 
  
  srslte_chest_ul_estimate(&q->chest, q->sf_symbols, q->ce, grant->L_prb, tti%10, cyclic_shift_for_dmrs, grant->n_prb);
  
  float noise_power = srslte_chest_ul_get_noise_estimate(&q->chest); 
  
  return srslte_pusch_decode(&q->pusch, &q->pusch_cfg, 
                              softbuffer, q->sf_symbols, 
                              q->ce, noise_power, 
                              rnti, data, 
                              uci_data);
}


int srslte_enb_ul_detect_prach(srslte_enb_ul_t *q, uint32_t tti, 
                               uint32_t freq_offset, cf_t *signal, 
                               uint32_t *indices, float *offsets, float *peak2avg)
{
  uint32_t nof_detected_prach = 0; 
  // consider the number of subframes the transmission must be anticipated 
  if (srslte_prach_tti_opportunity(&q->prach, tti, -1)) 
  {
    
    if (srslte_prach_detect_offset(&q->prach,
                                   freq_offset,
                                   &signal[q->prach.N_cp],
                                   SRSLTE_SF_LEN_PRB(q->cell.nof_prb),
                                   indices, 
                                   offsets,
                                   peak2avg,
                                   &nof_detected_prach)) 
    {
      fprintf(stderr, "Error detecting PRACH\n");
      return SRSLTE_ERROR; 
    }
  } 
  return (int) nof_detected_prach; 
}





