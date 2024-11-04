/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "E2AP-IEs"
 * 	found in "informationElementDefinition.asn"
 * 	`asn1c -pdu=auto -fincludes-quoted -fcompound-names -findirect-choice -fno-include-deps -no-gen-example -gen-APER`
 */

#ifndef	_CauseE2node_H_
#define	_CauseE2node_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CauseE2node {
	CauseE2node_e2node_component_unknown	= 0
	/*
	 * Enumeration is extensible
	 */
} e_CauseE2node;

/* CauseE2node */
typedef long	 CauseE2node_t;

/* Implementation */
extern asn_per_constraints_t asn_PER_type_CauseE2node_constr_1;
extern asn_TYPE_descriptor_t asn_DEF_CauseE2node;
extern const asn_INTEGER_specifics_t asn_SPC_CauseE2node_specs_1;
asn_struct_free_f CauseE2node_free;
asn_struct_print_f CauseE2node_print;
asn_constr_check_f CauseE2node_constraint;
ber_type_decoder_f CauseE2node_decode_ber;
der_type_encoder_f CauseE2node_encode_der;
xer_type_decoder_f CauseE2node_decode_xer;
xer_type_encoder_f CauseE2node_encode_xer;
jer_type_encoder_f CauseE2node_encode_jer;
oer_type_decoder_f CauseE2node_decode_oer;
oer_type_encoder_f CauseE2node_encode_oer;
per_type_decoder_f CauseE2node_decode_uper;
per_type_encoder_f CauseE2node_encode_uper;
per_type_decoder_f CauseE2node_decode_aper;
per_type_encoder_f CauseE2node_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _CauseE2node_H_ */
#include "asn_internal.h"