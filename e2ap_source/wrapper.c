#include <errno.h>
#include "wrapper.h"

size_t encode_E2AP_PDU(E2AP_PDU_t* pdu, void* buffer, size_t buf_size)
{
    asn_enc_rval_t encode_result;
    encode_result = aper_encode_to_buffer(&asn_DEF_E2AP_PDU, NULL, pdu, buffer, buf_size);
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    if(encode_result.encoded == -1) {
        fprintf(stderr, "Cannot encode %s: %s\n", encode_result.failed_type->name, strerror(errno));
        return -1;
    } else {
        return encode_result.encoded;
    }
}

E2AP_PDU_t* decode_E2AP_PDU(const void* buffer, size_t buf_size)
{
    asn_dec_rval_t decode_result;
    E2AP_PDU_t *pdu = 0;
    decode_result = aper_decode_complete(NULL, &asn_DEF_E2AP_PDU, (void **)&pdu, buffer, buf_size);
    if(decode_result.code == RC_OK) {
        return pdu;
    } else {
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
        return 0;
    }
}

/* RICsubscriptionRequest */
long e2ap_get_ric_subscription_request_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage)
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscription
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionRequest)
        {
            RICsubscriptionRequest_t *ric_subscription_request = &(initiatingMessage->value.choice.RICsubscriptionRequest);
            for (int i = 0; i < ric_subscription_request->protocolIEs.list.count; ++i )
            {
                if ( ric_subscription_request->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ric_subscription_request->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_request_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage)
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscription
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionRequest)
        {
            RICsubscriptionRequest_t *ricSubscriptionRequest = &initiatingMessage->value.choice.RICsubscriptionRequest;
            for (int i = 0; i < ricSubscriptionRequest->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionRequest->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    ricSubscriptionRequest->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t e2ap_encode_ric_subscription_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, long ranFunctionID, void *eventTriggerDefinition, size_t eventTriggerDefinitionSize, int actionCount, long *actionIds, long* actionTypes, RICactionDefinition *actionDefinitions, RICSubsequentAction *subsequentActionTypes) 
{
    E2AP_PDU_t *init = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
    if(!init) {
        fprintf(stderr, "alloc E2AP_PDU failed\n");
        return -1;
    }
    
    InitiatingMessage_t *initiatingMsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
    if(!initiatingMsg) {
        fprintf(stderr, "alloc InitiatingMessage failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    init->choice.initiatingMessage = initiatingMsg;
    init->present = E2AP_PDU_PR_initiatingMessage;

    initiatingMsg->procedureCode = ProcedureCode_id_RICsubscription;
    initiatingMsg->criticality = Criticality_reject;
    initiatingMsg->value.present = InitiatingMessage__value_PR_RICsubscriptionRequest;

    RICsubscriptionRequest_t *subscription_request = &initiatingMsg->value.choice.RICsubscriptionRequest;
    
    // request contains 5 IEs

    // RICrequestID
    RICsubscriptionRequest_IEs_t *ies_reqID = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
    if(!ies_reqID) {
        fprintf(stderr, "alloc RICrequestID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_reqID->criticality = Criticality_reject;
    ies_reqID->id = ProtocolIE_ID_id_RICrequestID;
    ies_reqID->value.present = RICsubscriptionRequest_IEs__value_PR_RICrequestID;
    RICrequestID_t *ricrequest_ie = &ies_reqID->value.choice.RICrequestID;
    ricrequest_ie->ricRequestorID = ricRequestorID;
    ricrequest_ie->ricInstanceID = ricRequestSequenceNumber;
    ASN_SEQUENCE_ADD(&subscription_request->protocolIEs.list, ies_reqID);

    // RICfunctionID
    RICsubscriptionRequest_IEs_t *ies_ranfunc = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
    if(!ies_ranfunc) {
        fprintf(stderr, "alloc RICfunctionID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_ranfunc->criticality = Criticality_reject;
    ies_ranfunc->id = ProtocolIE_ID_id_RANfunctionID;
    ies_ranfunc->value.present = RICsubscriptionRequest_IEs__value_PR_RANfunctionID;
    RANfunctionID_t *ranfunction_ie = &ies_ranfunc->value.choice.RANfunctionID;
    *ranfunction_ie = ranFunctionID;
    ASN_SEQUENCE_ADD(&subscription_request->protocolIEs.list, ies_ranfunc);

    // RICsubscription
    RICsubscriptionRequest_IEs_t *ies_subscription = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
    if(!ies_subscription) {
        fprintf(stderr, "alloc RICsubscription failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_subscription->criticality = Criticality_reject;
    ies_subscription->id = ProtocolIE_ID_id_RICsubscriptionDetails;
    ies_subscription->value.present = RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails;
    RICsubscriptionDetails_t *ricsubscription_ie = &ies_subscription->value.choice.RICsubscriptionDetails;

    // RICeventTriggerDefinition
    RICeventTriggerDefinition_t *eventTrigger = &ricsubscription_ie->ricEventTriggerDefinition;
    eventTrigger->buf = (uint8_t *)calloc(1, eventTriggerDefinitionSize);
    if(!eventTrigger->buf) {
        fprintf(stderr, "alloc eventTrigger failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    memcpy(eventTrigger->buf, eventTriggerDefinition, eventTriggerDefinitionSize);
    eventTrigger->size = eventTriggerDefinitionSize;
    
    // RICactions-ToBeSetup-List
    RICactions_ToBeSetup_List_t *ricActions = &ricsubscription_ie->ricAction_ToBeSetup_List;
    int index = 0;
    while (index < actionCount) {
        RICaction_ToBeSetup_ItemIEs_t *ies_action = (RICaction_ToBeSetup_ItemIEs_t *)calloc(1, sizeof(RICaction_ToBeSetup_ItemIEs_t));
        if(!ies_action) {
            fprintf(stderr, "alloc RICaction failed\n");
            ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
            return -1;
        }

        ies_action->criticality = Criticality_reject;
        ies_action->id = ProtocolIE_ID_id_RICaction_ToBeSetup_Item;
        ies_action->value.present = RICaction_ToBeSetup_ItemIEs__value_PR_RICaction_ToBeSetup_Item;
        RICaction_ToBeSetup_Item_t *ricaction_ie = &ies_action->value.choice.RICaction_ToBeSetup_Item;
        ricaction_ie->ricActionID = actionIds[index];
        ricaction_ie->ricActionType = actionTypes[index];

        int actionDefinitionSize = actionDefinitions[index].size;
        if(actionDefinitionSize != 0) {
            RICactionDefinition_t *actionDefinition = ricaction_ie->ricActionDefinition;
            
            actionDefinition->buf = (uint8_t *)calloc(1, actionDefinitionSize);
            if(!actionDefinition->buf) {
                fprintf(stderr, "alloc actionDefinition[%d] failed\n", index);
                ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
                return -1;
            }

            memcpy(actionDefinition->buf, actionDefinitions[index].actionDefinition, actionDefinitionSize);
            actionDefinition->size = actionDefinitionSize;
        }

        if(subsequentActionTypes[index].isValid != 0) {
            RICsubsequentAction_t *subsequentAction = ricaction_ie->ricSubsequentAction;
            subsequentAction->ricSubsequentActionType = subsequentActionTypes[index].subsequentActionType;
            subsequentAction->ricTimeToWait = subsequentActionTypes[index].timeToWait;
        }

        ASN_SEQUENCE_ADD(&ricActions->list, ies_action);
        index++;
    }
    ASN_SEQUENCE_ADD(&subscription_request->protocolIEs.list, ies_subscription);

    return encode_E2AP_PDU(init, buffer, buf_size);
}

/* RICsubscriptionResponse */
long e2ap_get_ric_subscription_response_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionResponse)
        {
            RICsubscriptionResponse_t *ricSubscriptionResponse = &successfulOutcome->value.choice.RICsubscriptionResponse;
            for (int i = 0; i < ricSubscriptionResponse->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ricSubscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_response_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionResponse)
        {
            RICsubscriptionResponse_t *ricSubscriptionResponse = &successfulOutcome->value.choice.RICsubscriptionResponse;
            for (int i = 0; i < ricSubscriptionResponse->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    ricSubscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

RICsubscriptionResponseMsg* e2ap_decode_ric_subscription_response_message(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome)
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionResponse)
        {
            RICsubscriptionResponse_t *subscriptionResponse = &(successfulOutcome->value.choice.RICsubscriptionResponse);
            RICsubscriptionResponseMsg *msg = (RICsubscriptionResponseMsg *)calloc(1, sizeof(RICsubscriptionResponseMsg));
            for (int i = 0; i < subscriptionResponse->protocolIEs.list.count; ++i )
            {
                if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID) {
                    msg->requestorID = subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricRequestorID;
                    msg->requestSequenceNumber = subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                }
                else if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RANfunctionID) {
                    msg->ranfunctionID = subscriptionResponse->protocolIEs.list.array[i]->value.choice.RANfunctionID;
                }
                else if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICactions_Admitted) {
                    RICaction_Admitted_List_t *ricActionAdmittedList = &(subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICaction_Admitted_List);
                    int index = 0;
                    while (index < ricActionAdmittedList->list.count) {
                        RICaction_Admitted_ItemIEs_t *ricActionAdmittedItem = (RICaction_Admitted_ItemIEs_t *)ricActionAdmittedList->list.array[index];
                        if (ricActionAdmittedItem->id == ProtocolIE_ID_id_RICaction_Admitted_Item) {
                            msg->ricActionAdmittedList.ricActionID[index] = ricActionAdmittedItem->value.choice.RICaction_Admitted_Item.ricActionID;
                        }
                        index++;
                    }
                    msg->ricActionAdmittedList.count = index;
                }
                else if (subscriptionResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICactions_NotAdmitted) {
                    RICaction_NotAdmitted_List_t *ricActionNotAdmittedList = &(subscriptionResponse->protocolIEs.list.array[i]->value.choice.RICaction_NotAdmitted_List);
                    int index = 0;
                    while (index < ricActionNotAdmittedList->list.count) {
                        RICaction_NotAdmitted_ItemIEs_t *ricActionNotAdmittedItem = (RICaction_NotAdmitted_ItemIEs_t *)ricActionNotAdmittedList->list.array[index];
                        if (ricActionNotAdmittedItem->id == ProtocolIE_ID_id_RICaction_NotAdmitted_Item) {
                            msg->ricActionNotAdmittedList.ricActionID[index] = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.ricActionID;
                            int RICcauseType = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.present;
                            switch(RICcauseType) {
                                case Cause_PR_ricRequest:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_ricRequest;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.ricRequest;
                                    break;
                                case Cause_PR_ricService:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_ricService;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.ricService;
                                    break;
                                case Cause_PR_transport:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_transport;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.transport;
                                    break;
                                case Cause_PR_protocol:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_protocol;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.protocol;
                                    break;
                                case Cause_PR_misc:
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseType = Cause_PR_misc;
                                    msg->ricActionNotAdmittedList.ricCause[index].ricCauseID = ricActionNotAdmittedItem->value.choice.RICaction_NotAdmitted_Item.cause.choice.misc;
                                    break;
                            }
                        }
                        index++;
                    }
                    msg->ricActionNotAdmittedList.count = index;
                }
            }
            return msg;
        }
    }
    return NULL;
}

/* RICsubscriptionFailure */
long e2ap_get_ric_subscription_failure_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_unsuccessfulOutcome )
    {
        UnsuccessfulOutcome_t* unsuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
        if ( unsuccessfulOutcome->procedureCode == ProcedureCode_id_RICsubscription
            && unsuccessfulOutcome->value.present == UnsuccessfulOutcome__value_PR_RICsubscriptionFailure)
        {
            RICsubscriptionFailure_t *ricSubscriptionFailure = &unsuccessfulOutcome->value.choice.RICsubscriptionFailure;
            for (int i = 0; i < ricSubscriptionFailure->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ricSubscriptionFailure->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

/* RICsubscriptionDeleteRequest */
long e2ap_get_ric_subscription_delete_request_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage )
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionDeleteRequest )
        {
            RICsubscriptionDeleteRequest_t *subscriptionDeleteRequest = &initiatingMessage->value.choice.RICsubscriptionDeleteRequest;
            for (int i = 0; i < subscriptionDeleteRequest->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteRequest->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = subscriptionDeleteRequest->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_delete_request_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage )
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICsubscriptionDeleteRequest )
        {
            RICsubscriptionDeleteRequest_t* subscriptionDeleteRequest = &initiatingMessage->value.choice.RICsubscriptionDeleteRequest;
            for (int i = 0; i < subscriptionDeleteRequest->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteRequest->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    subscriptionDeleteRequest->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t e2ap_encode_ric_subscription_delete_request_message(void *buffer, size_t buf_size, long ricRequestorID, long ricRequestSequenceNumber, long ranFunctionID)
{
    E2AP_PDU_t *init = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
    if(!init) {
        fprintf(stderr, "alloc E2AP_PDU failed\n");
        return -1;
    }

    InitiatingMessage_t *initiatingMsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
    if(!initiatingMsg) {
        fprintf(stderr, "alloc InitiatingMessage failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    init->choice.initiatingMessage = initiatingMsg;
    init->present = E2AP_PDU_PR_initiatingMessage;

    initiatingMsg->procedureCode = ProcedureCode_id_RICsubscriptionDelete;
    initiatingMsg->criticality = Criticality_reject;
    initiatingMsg->value.present = InitiatingMessage__value_PR_RICsubscriptionDeleteRequest;

    RICsubscriptionDeleteRequest_t *subscription_delete_request = &initiatingMsg->value.choice.RICsubscriptionDeleteRequest;
    
    // request contains 2 IEs

    // RICrequestID
    RICsubscriptionDeleteRequest_IEs_t *ies_reqID = (RICsubscriptionDeleteRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionDeleteRequest_IEs_t));
    if(!ies_reqID) {
        fprintf(stderr, "alloc RICrequestID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_reqID->criticality = Criticality_reject;
    ies_reqID->id = ProtocolIE_ID_id_RICrequestID;
    ies_reqID->value.present = RICsubscriptionDeleteRequest_IEs__value_PR_RICrequestID;
    RICrequestID_t *ricrequest_ie = &ies_reqID->value.choice.RICrequestID;
    ricrequest_ie->ricRequestorID = ricRequestorID;
    ricrequest_ie->ricInstanceID = ricRequestSequenceNumber;
    ASN_SEQUENCE_ADD(&subscription_delete_request->protocolIEs.list, ies_reqID);

    // RICfunctionID
    RICsubscriptionDeleteRequest_IEs_t *ies_ranfunc = (RICsubscriptionDeleteRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionDeleteRequest_IEs_t));
    if(!ies_ranfunc) {
        fprintf(stderr, "alloc RICfunctionID failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    ies_ranfunc->criticality = Criticality_reject;
    ies_ranfunc->id = ProtocolIE_ID_id_RANfunctionID;
    ies_ranfunc->value.present = RICsubscriptionDeleteRequest_IEs__value_PR_RANfunctionID;
    RANfunctionID_t *ranfunction_ie = &ies_ranfunc->value.choice.RANfunctionID;
    *ranfunction_ie = ranFunctionID;
    ASN_SEQUENCE_ADD(&subscription_delete_request->protocolIEs.list, ies_ranfunc);

    return encode_E2AP_PDU(init, buffer, buf_size);
}

/* RICsubscriptionDeleteResponse */
long e2ap_get_ric_subscription_delete_response_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionDeleteResponse )
        {
            RICsubscriptionDeleteResponse_t* subscriptionDeleteResponse = &successfulOutcome->value.choice.RICsubscriptionDeleteResponse;
            for (int i = 0; i < subscriptionDeleteResponse->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = subscriptionDeleteResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

ssize_t  e2ap_set_ric_subscription_delete_response_sequence_number(void *buffer, size_t buf_size, long sequence_number)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome )
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICsubscriptionDeleteResponse )
        {
            RICsubscriptionDeleteResponse_t* subscriptionDeleteResponse = &successfulOutcome->value.choice.RICsubscriptionDeleteResponse;
            for (int i = 0; i < subscriptionDeleteResponse->protocolIEs.list.count; ++i )
            {
                if ( subscriptionDeleteResponse->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    subscriptionDeleteResponse->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID = sequence_number;
                    return encode_E2AP_PDU(pdu, buffer, buf_size);
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

/* RICsubscriptionDeleteFailure */
long e2ap_get_ric_subscription_delete_failure_sequence_number(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_unsuccessfulOutcome )
    {
        UnsuccessfulOutcome_t* unsuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
        if ( unsuccessfulOutcome->procedureCode == ProcedureCode_id_RICsubscriptionDelete
            && unsuccessfulOutcome->value.present == UnsuccessfulOutcome__value_PR_RICsubscriptionDeleteFailure)
        {
            RICsubscriptionDeleteFailure_t *ricSubscriptionDeleteFailure = &unsuccessfulOutcome->value.choice.RICsubscriptionDeleteFailure;
            for (int i = 0; i < ricSubscriptionDeleteFailure->protocolIEs.list.count; ++i )
            {
                if ( ricSubscriptionDeleteFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID )
                {
                    long sequenceNumber = ricSubscriptionDeleteFailure->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                    return sequenceNumber;
                }
            }
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return -1;
}

/* RICindication */

RICindicationMsg* e2ap_decode_ric_indication_message(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage)
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICindication
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICindication)
        {
            RICindication_t *indication = &(initiatingMessage->value.choice.RICindication);
            RICindicationMsg *msg = (RICindicationMsg *)calloc(1, sizeof(RICindicationMsg));
            for (int i = 0; i < indication->protocolIEs.list.count; ++i )
            {
                if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID) {
                    msg->requestorID = indication->protocolIEs.list.array[i]->value.choice.RICrequestID.ricRequestorID;
                    msg->requestSequenceNumber = indication->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                }
                else if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RANfunctionID) {
                    msg->ranfunctionID = indication->protocolIEs.list.array[i]->value.choice.RANfunctionID;
                }
                else if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICactionID) {
                    msg->actionID = indication->protocolIEs.list.array[i]->value.choice.RICactionID;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationSN) {
                    msg->indicationSN = indication->protocolIEs.list.array[i]->value.choice.RICindicationSN;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationType) {
                    msg->indicationType = indication->protocolIEs.list.array[i]->value.choice.RICindicationType;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationHeader) {
                    size_t headerSize = indication->protocolIEs.list.array[i]->value.choice.RICindicationHeader.size;
                    msg->indicationHeader = calloc(1, headerSize);
                    if (!msg->indicationHeader) {
                        fprintf(stderr, "alloc RICindicationHeader failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->indicationHeader, indication->protocolIEs.list.array[i]->value.choice.RICindicationHeader.buf, headerSize);
                    msg->indicationHeaderSize = headerSize;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationMessage) {
                    size_t messsageSize = indication->protocolIEs.list.array[i]->value.choice.RICindicationMessage.size;
                    msg->indicationMessage = calloc(1, messsageSize);
                    if (!msg->indicationMessage) {
                        fprintf(stderr, "alloc RICindicationMessage failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->indicationMessage, indication->protocolIEs.list.array[i]->value.choice.RICindicationMessage.buf, messsageSize);
                    msg->indicationMessageSize = messsageSize;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcallProcessID) {
                    size_t callProcessIDSize = indication->protocolIEs.list.array[i]->value.choice.RICcallProcessID.size;
                    msg->callProcessID = calloc(1, callProcessIDSize);
                    if (!msg->callProcessID) {
                        fprintf(stderr, "alloc RICcallProcessID failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->callProcessID, indication->protocolIEs.list.array[i]->value.choice.RICcallProcessID.buf, callProcessIDSize);
                    msg->callProcessIDSize = callProcessIDSize;
                }
            }
            return msg;
        }
    }

    if(pdu != NULL) 
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return NULL;
}


RICindicationMsg* e2ap_decode_ric_indication_m()
{
    		 
		 
   		FILE *fp3 = fopen("testfile1.txt", "r");
		if (fp3==NULL)
		{
		 printf("\nFAILED TO OPEN FILE SANDY3.TXT");
		 return NULL;
		}
                fseek(fp3, 0L, SEEK_END);
                long numbytes = ftell(fp3);
                fseek(fp3, 0L, SEEK_SET);
                char* text = (char*)calloc(numbytes, sizeof(char));
                fread(text, sizeof(char), numbytes, fp3);
                fclose(fp3);
                printf(text);
                E2AP_PDU_t *pdu=0;
                asn_dec_rval_t lol =xer_decode(0,&asn_DEF_E2AP_PDU, (void **)&pdu,text,numbytes);
                printf("\nxer decode result =%d",lol.code);
		FILE *fp4 = fopen("testfile1.txt", "w");
                int r2=asn_fprint(fp4,&asn_DEF_E2AP_PDU,pdu);
                fclose(fp4);
                if (r2==-1)
                         fprintf(stderr, "failed asn_fprint r2\n");
                else
                         fprintf(stderr, "successfull asn_fprint r2\n");


    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_initiatingMessage)
    {
        InitiatingMessage_t* initiatingMessage = pdu->choice.initiatingMessage;
        if ( initiatingMessage->procedureCode == ProcedureCode_id_RICindication
            && initiatingMessage->value.present == InitiatingMessage__value_PR_RICindication)
        {
            RICindication_t *indication = &(initiatingMessage->value.choice.RICindication);
            RICindicationMsg *msg = (RICindicationMsg *)calloc(1, sizeof(RICindicationMsg));
            for (int i = 0; i < indication->protocolIEs.list.count; ++i )
            {
                if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID) {
                    msg->requestorID = indication->protocolIEs.list.array[i]->value.choice.RICrequestID.ricRequestorID;
                    msg->requestSequenceNumber = indication->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                }
                else if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RANfunctionID) {
                    msg->ranfunctionID = indication->protocolIEs.list.array[i]->value.choice.RANfunctionID;
                }
                else if (indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICactionID) {
                    msg->actionID = indication->protocolIEs.list.array[i]->value.choice.RICactionID;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationSN) {
                    msg->indicationSN = indication->protocolIEs.list.array[i]->value.choice.RICindicationSN;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationType) {
                    msg->indicationType = indication->protocolIEs.list.array[i]->value.choice.RICindicationType;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationHeader) {
                    size_t headerSize = indication->protocolIEs.list.array[i]->value.choice.RICindicationHeader.size;
                    msg->indicationHeader = calloc(1, headerSize);
                    if (!msg->indicationHeader) {
                        fprintf(stderr, "alloc RICindicationHeader failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->indicationHeader, indication->protocolIEs.list.array[i]->value.choice.RICindicationHeader.buf, headerSize);
                    msg->indicationHeaderSize = headerSize;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICindicationMessage) {
                    size_t messsageSize = indication->protocolIEs.list.array[i]->value.choice.RICindicationMessage.size;
                    msg->indicationMessage = calloc(1, messsageSize);
                    if (!msg->indicationMessage) {
                        fprintf(stderr, "alloc RICindicationMessage failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->indicationMessage, indication->protocolIEs.list.array[i]->value.choice.RICindicationMessage.buf, messsageSize);
                    msg->indicationMessageSize = messsageSize;
                }
                else if(indication->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcallProcessID) {
                    size_t callProcessIDSize = indication->protocolIEs.list.array[i]->value.choice.RICcallProcessID.size;
                    msg->callProcessID = calloc(1, callProcessIDSize);
                    if (!msg->callProcessID) {
                        fprintf(stderr, "alloc RICcallProcessID failed\n");
                        e2ap_free_decoded_ric_indication_message(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->callProcessID, indication->protocolIEs.list.array[i]->value.choice.RICcallProcessID.buf, callProcessIDSize);
                    msg->callProcessIDSize = callProcessIDSize;
                }
            }
/*
		RICindicationHeader_t *hdr;
		hdr=calloc(1, sizeof(RICindicationHeader_t));
		memcpy( hdr->buf,msg->indicationHeader,msg->indicationHeaderSize);
		hdr->size=msg->indicationHeaderSize;
	     xer_fprint(stdout, &asn_DEF_RICindicationHeader,hdr);
	     RICindicationMessage_t *indm;
	     indm=calloc(1, sizeof(RICindicationMessage_t));
	     memcpy(indm->buf, msg->indicationMessage,msg->indicationMessageSize);
	     indm->size=msg->indicationMessageSize;
	  xer_fprint(stdout, &asn_DEF_RICindicationMessage, indm);
*/	  
//	  fprintf(stderr, "\nreturning msg\n");

	    return msg;
        }
    }
 //fprintf(stderr, "\nreturning null");
    if(pdu != NULL)
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return NULL;
}

void e2ap_free_decoded_ric_indication_message(RICindicationMsg* msg) {
    if(msg == NULL) {
        return;
    }

    if(msg->indicationHeader != NULL) {
        free(msg->indicationHeader);
        msg->indicationHeader = NULL;
    }
    if(msg->indicationMessage != NULL) {
        free(msg->indicationMessage);
        msg->indicationMessage = NULL;
    }
    if(msg->callProcessID != NULL) {
        free(msg->callProcessID);
        msg->callProcessID = NULL;
    }
    free(msg);
    msg = NULL;
}

RICControlAcknowledge* e2ap_decode_ric_control_acknowledge_message(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_successfulOutcome)
    {
        SuccessfulOutcome_t* successfulOutcome = pdu->choice.successfulOutcome;
        if ( successfulOutcome->procedureCode == ProcedureCode_id_RICcontrol
            && successfulOutcome->value.present == SuccessfulOutcome__value_PR_RICcontrolAcknowledge)
        {
		RICcontrolAcknowledge_t *controlAck = &(successfulOutcome->value.choice.RICcontrolAcknowledge);
            	RICControlAcknowledge *msg = (RICControlAcknowledge *)calloc(1, sizeof(RICControlAcknowledge));
		int i = 0;
		 for (i; i < controlAck->protocolIEs.list.count; ++i )
            {
		if(controlAck->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID)
		{
                    msg->requestorID = controlAck->protocolIEs.list.array[i]->value.choice.RICrequestID.ricRequestorID;
                    msg->instanceID = controlAck->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                }
                else if (controlAck->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RANfunctionID) {
                    msg->ranfunctionID = controlAck->protocolIEs.list.array[i]->value.choice.RANfunctionID;
                }
		else if(controlAck->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcallProcessID) {
                    size_t callProcessIDSize = controlAck->protocolIEs.list.array[i]->value.choice.RICcallProcessID.size;
                    msg->callProcessID = calloc(1, callProcessIDSize);
                    if (!msg->callProcessID) {
                        fprintf(stderr, "alloc RICcallProcessID failed\n");
                        e2ap_free_decoded_ric_control_ack(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->callProcessID, controlAck->protocolIEs.list.array[i]->value.choice.RICcallProcessID.buf, callProcessIDSize);
                    msg->callProcessIDSize = callProcessIDSize;
                }
		else if(controlAck->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcontrolOutcome) {
                    size_t ricControlOutComeSize = controlAck->protocolIEs.list.array[i]->value.choice.RICcontrolOutcome.size;
                    msg->ricControlOutCome = calloc(1, ricControlOutComeSize);
                    if (!msg->ricControlOutCome) {
                        fprintf(stderr, "alloc ricControlOutCome failed\n");
                        e2ap_free_decoded_ric_control_ack(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
                        return NULL;
                    }

                    memcpy(msg->ricControlOutCome, controlAck->protocolIEs.list.array[i]->value.choice.RICcontrolOutcome.buf, ricControlOutComeSize);
                    msg->ricControlOutComeSize = ricControlOutComeSize;
                }
	}
		 if(pdu != NULL)
		   	ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
		return msg;
	}
        }

    if(pdu != NULL)
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    return NULL;
}

void e2ap_free_decoded_ric_control_ack(RICControlAcknowledge* msg) {
    if(msg == NULL) {
        return;
    }
    if(msg->callProcessID != NULL) {
        free(msg->callProcessID);
        msg->callProcessID = NULL;
    }
    if(msg->ricControlOutCome != NULL) {
        free(msg->ricControlOutCome);
        msg->ricControlOutCome = NULL;
    }
        free(msg);
    msg = NULL;
}

RICControlFailure* e2ap_decode_ric_control_failure_message(void *buffer, size_t buf_size)
{
    E2AP_PDU_t *pdu = decode_E2AP_PDU(buffer, buf_size);
    if ( pdu != NULL && pdu->present == E2AP_PDU_PR_unsuccessfulOutcome)
    {
        UnsuccessfulOutcome_t* unSuccessfulOutcome = pdu->choice.unsuccessfulOutcome;
        if ( unSuccessfulOutcome->procedureCode == ProcedureCode_id_RICcontrol
            && unSuccessfulOutcome->value.present == UnsuccessfulOutcome__value_PR_RICcontrolFailure)
        {
                RICcontrolFailure_t *controlFailure = &(unSuccessfulOutcome->value.choice.RICcontrolFailure);
                RICControlFailure *msg = (RICControlFailure *)calloc(1, sizeof(RICControlFailure));
                int i = 0;
                 for (i; i < controlFailure->protocolIEs.list.count; ++i )
            {
                if(controlFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICrequestID)
                {
                    msg->requestorID = controlFailure->protocolIEs.list.array[i]->value.choice.RICrequestID.ricRequestorID;
                    msg->instanceID = controlFailure->protocolIEs.list.array[i]->value.choice.RICrequestID.ricInstanceID;
                }
                else if (controlFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RANfunctionID) {
                    msg->ranfunctionID = controlFailure->protocolIEs.list.array[i]->value.choice.RANfunctionID;
                }
                else if(controlFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcallProcessID) {
                    size_t callProcessIDSize = controlFailure->protocolIEs.list.array[i]->value.choice.RICcallProcessID.size;
                    msg->callProcessID = calloc(1, callProcessIDSize);
                    if (!msg->callProcessID) {
                        fprintf(stderr, "alloc RICcallProcessID failed\n");
                        e2ap_free_decoded_ric_control_failure(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
			 return NULL;
                    }

                memcpy(msg->callProcessID, controlFailure->protocolIEs.list.array[i]->value.choice.RICcallProcessID.buf, callProcessIDSize);
                    msg->callProcessIDSize = callProcessIDSize;
                }
                else if(controlFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcontrolOutcome) {
                        msg->causeType = controlFailure->protocolIEs.list.array[i]->value.choice.Cause.present;
                        if (msg->causeType == Cause_PR_ricRequest) {
                                msg->causeValue = controlFailure->protocolIEs.list.array[i]->value.choice.Cause.choice.ricRequest;
                        } else if (msg->causeType == Cause_PR_ricService) {
                                msg->causeValue = controlFailure->protocolIEs.list.array[i]->value.choice.Cause.choice.ricService;
                        } else if (msg->causeType == Cause_PR_transport) {
                                msg->causeValue = controlFailure->protocolIEs.list.array[i]->value.choice.Cause.choice.transport;
                        } else if (msg->causeType == Cause_PR_protocol) {
                                msg->causeValue = controlFailure->protocolIEs.list.array[i]->value.choice.Cause.choice.protocol;
                        } else if (msg->causeType == Cause_PR_misc) {
                                msg->causeValue = controlFailure->protocolIEs.list.array[i]->value.choice.Cause.choice.misc;
                        }else {
                                msg->causeType == Cause_PR_NOTHING;
                        }
                }
                else if(controlFailure->protocolIEs.list.array[i]->id == ProtocolIE_ID_id_RICcontrolOutcome) {
                    size_t ricControlOutComeSize = controlFailure->protocolIEs.list.array[i]->value.choice.RICcontrolOutcome.size;
                    msg->ricControlOutCome = calloc(1, ricControlOutComeSize);
                    if (!msg->ricControlOutCome) {
                        fprintf(stderr, "alloc ricControlOutCome failed\n");
                        e2ap_free_decoded_ric_control_failure(msg);
                        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
			return NULL;
                    }

                    memcpy(msg->ricControlOutCome, controlFailure->protocolIEs.list.array[i]->value.choice.RICcontrolOutcome.buf, ricControlOutComeSize);
                    msg->ricControlOutComeSize = ricControlOutComeSize;

		}
        }
		 if(pdu != NULL)
                     ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);

                return msg;
        }
        }

        if(pdu != NULL)
                ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);

        return NULL;
}

void e2ap_free_decoded_ric_control_failure(RICControlFailure* msg) {
    if(msg == NULL) {
        return;
    }
    if(msg->callProcessID != NULL) {
        free(msg->callProcessID);
        msg->callProcessID = NULL;
    }
    if(msg->ricControlOutCome != NULL) {
        free(msg->ricControlOutCome);
        msg->ricControlOutCome = NULL;
    }
        free(msg);
    msg = NULL;
}


ssize_t e2ap_encode_ric_control_request_message(
    void *buffer, size_t buf_size,
    long ricRequestorID,
    long ricRequestSequenceNumber,
    long ranFunctionID,
    void *ricCallProcessID, size_t ricCallProcessIDSize,
    void *ricControlHdr, size_t ricControlHdrSize,
    void *ricControlMsg, size_t ricControlMsgSize,
    long ricControlAckRequest)
{
    E2AP_PDU_t *init = (E2AP_PDU_t *)calloc(1, sizeof(E2AP_PDU_t));
    if (!init) {
        fprintf(stderr, "alloc E2AP_PDU failed\n");
        return -1;
    }

    InitiatingMessage_t *initiatingMsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
    if (!initiatingMsg) {
        fprintf(stderr, "alloc InitiatingMessage failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }

    init->choice.initiatingMessage = initiatingMsg;
    init->present = E2AP_PDU_PR_initiatingMessage;

    initiatingMsg->procedureCode = ProcedureCode_id_RICcontrol;
    initiatingMsg->criticality = Criticality_reject;
    initiatingMsg->value.present = InitiatingMessage__value_PR_RICcontrolRequest;

    RICcontrolRequest_t *control_request = &initiatingMsg->value.choice.RICcontrolRequest;

    /* ============================================================
     * IE 1: id-RICrequestID (29) — MANDATORY
     * ============================================================ */
    RICcontrolRequest_IEs_t *ies_reqID = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ies_reqID) {
        fprintf(stderr, "alloc RICrequestID IE failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    ies_reqID->criticality = Criticality_reject;
    ies_reqID->id = ProtocolIE_ID_id_RICrequestID;
    ies_reqID->value.present = RICcontrolRequest_IEs__value_PR_RICrequestID;
    ies_reqID->value.choice.RICrequestID.ricRequestorID = ricRequestorID;
    ies_reqID->value.choice.RICrequestID.ricInstanceID = ricRequestSequenceNumber;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, ies_reqID);

    /* ============================================================
     * IE 2: id-RANfunctionID (5) — MANDATORY
     * ============================================================ */
    RICcontrolRequest_IEs_t *ies_ranfunc = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ies_ranfunc) {
        fprintf(stderr, "alloc RANfunctionID IE failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    ies_ranfunc->criticality = Criticality_reject;
    ies_ranfunc->id = ProtocolIE_ID_id_RANfunctionID;
    ies_ranfunc->value.present = RICcontrolRequest_IEs__value_PR_RANfunctionID;
    ies_ranfunc->value.choice.RANfunctionID = ranFunctionID;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, ies_ranfunc);

    /* ============================================================
     * IE 3: id-RICcallProcessID (20) — OPTIONAL
     * ============================================================ */
    if (ricCallProcessID != NULL && ricCallProcessIDSize > 0) {
        RICcontrolRequest_IEs_t *ies_callproc = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
        if (!ies_callproc) {
            fprintf(stderr, "alloc RICcallProcessID IE failed\n");
            ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
            return -1;
        }
        ies_callproc->criticality = Criticality_reject;
        ies_callproc->id = ProtocolIE_ID_id_RICcallProcessID;
        ies_callproc->value.present = RICcontrolRequest_IEs__value_PR_RICcallProcessID;
        RICcallProcessID_t *callProcID = &ies_callproc->value.choice.RICcallProcessID;
        callProcID->buf = (uint8_t *)calloc(1, ricCallProcessIDSize);
        if (!callProcID->buf) {
            fprintf(stderr, "alloc RICcallProcessID buf failed\n");
            free(ies_callproc);
            ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
            return -1;
        }
        memcpy(callProcID->buf, ricCallProcessID, ricCallProcessIDSize);
        callProcID->size = ricCallProcessIDSize;
        ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, ies_callproc);
    }

    /* ============================================================
     * IE 4: id-RICcontrolHeader (22) — MANDATORY
     * ============================================================ */
    RICcontrolRequest_IEs_t *ies_ctrlhdr = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ies_ctrlhdr) {
        fprintf(stderr, "alloc RICcontrolHeader IE failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    ies_ctrlhdr->criticality = Criticality_reject;
    ies_ctrlhdr->id = ProtocolIE_ID_id_RICcontrolHeader;
    ies_ctrlhdr->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolHeader;
    RICcontrolHeader_t *ctrlHdr = &ies_ctrlhdr->value.choice.RICcontrolHeader;
    ctrlHdr->buf = (uint8_t *)calloc(1, ricControlHdrSize);
    if (!ctrlHdr->buf) {
        fprintf(stderr, "alloc RICcontrolHeader buf failed\n");
        free(ies_ctrlhdr);
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    memcpy(ctrlHdr->buf, ricControlHdr, ricControlHdrSize);
    ctrlHdr->size = ricControlHdrSize;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, ies_ctrlhdr);

    /* ============================================================
     * IE 5: id-RICcontrolMessage (23) — MANDATORY
     * ============================================================ */
    RICcontrolRequest_IEs_t *ies_ctrlmsg = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    if (!ies_ctrlmsg) {
        fprintf(stderr, "alloc RICcontrolMessage IE failed\n");
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    ies_ctrlmsg->criticality = Criticality_reject;
    ies_ctrlmsg->id = ProtocolIE_ID_id_RICcontrolMessage;
    ies_ctrlmsg->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolMessage;
    RICcontrolMessage_t *ctrlMsg = &ies_ctrlmsg->value.choice.RICcontrolMessage;
    ctrlMsg->buf = (uint8_t *)calloc(1, ricControlMsgSize);
    if (!ctrlMsg->buf) {
        fprintf(stderr, "alloc RICcontrolMessage buf failed\n");
        free(ies_ctrlmsg);
        ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
        return -1;
    }
    memcpy(ctrlMsg->buf, ricControlMsg, ricControlMsgSize);
    ctrlMsg->size = ricControlMsgSize;
    ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, ies_ctrlmsg);

    /* ============================================================
     * IE 6: id-RICcontrolAckRequest (21) — OPTIONAL
     * ============================================================ */
    if (ricControlAckRequest >= 0) {
        RICcontrolRequest_IEs_t *ies_ackreq = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
        if (!ies_ackreq) {
            fprintf(stderr, "alloc RICcontrolAckRequest IE failed\n");
            ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, init);
            return -1;
        }
        ies_ackreq->criticality = Criticality_reject;
        ies_ackreq->id = ProtocolIE_ID_id_RICcontrolAckRequest;
        ies_ackreq->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolAckRequest;
        ies_ackreq->value.choice.RICcontrolAckRequest = ricControlAckRequest;
        ASN_SEQUENCE_ADD(&control_request->protocolIEs.list, ies_ackreq);
    }

    fprintf(stderr, "showing xer of asn_DEF_E2AP_PDU data\n");
    xer_fprint(stderr, &asn_DEF_E2AP_PDU, init);
    fprintf(stderr, "\n");
    fprintf(stderr, "After xer of asn_DEF_E2AP_PDU data\n");

    return encode_E2AP_PDU(init, buffer, buf_size);
}