module mms;

@load ./helper

export {

    redef enum Log::ID += { LOG_VAA };

    type VAA: record {
        ts:         time     &log;
        uid:        string   &log;
        id:         conn_id  &log;
        variable:   string   &log;
        attributes: string   &log &optional;
        success:    bool     &log;
        diag:       string   &log &optional;
    };

    global log_mms_var_attributes: event(rec: VAA);

    const log_var_attributes: bool = T &redef;

    ## The maximum number of bytes that a single string field can contain when
	## logging. If a string reaches this limit, the log output for the field will be
	## truncated. Setting this to zero disables the limiting. MMS has no maximum
	## length for various fields such as the value, so this is set to zero by default.
	##
	## .. zeek:see:: Log::default_max_field_string_bytes
	const default_max_field_string_bytes = 0 &redef;
}

event zeek_init() &priority=5
{
    Log::create_stream(mms::LOG_VAA,
        [$columns = VAA,
        $ev = log_mms_var_attributes,
        $path="mms_var_attributes",
        $max_field_string_bytes=mms::default_max_field_string_bytes
        ]
    );
}

event VariableAccessAttributes(c: connection, request: GetVariableAccessAttributes_Request, response: GetVariableAccessAttributes_Response) {

    if(!log_var_attributes) return;

    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $variable=objectName_to_string(request$name),
        $attributes=typeSpecification_to_string(response$typeSpecification, objectName_to_string(request$name)),
        $success=T
    );

    Log::write(LOG_VAA, rec);
}

event VariableAccessAttributesError(c: connection, request: GetVariableAccessAttributes_Request, response: Confirmed_ErrorPDU) {

    if(!log_var_attributes) return;

    local rec=record(
        $ts=network_time(),
        $uid=c$uid,
        $id=c$id,
        $variable=objectName_to_string(request$name),
        $success=F,
        $diag=errorClass_to_string(response$serviceError)
    );

    Log::write(LOG_VAA, rec);
}