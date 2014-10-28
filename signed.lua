local create_user = function(key, secret)
	storage['key:'..key] = secret
	storage['nonce:'..key] = 0
end

local delete_user = function(key)
	storage['key:'..key] = nil
	storage['nonce:'..key] = nil
end

local authenticate = function(request)
	local query = request.path.."?"..request.querystring;

	local key = request.headers["Key"];
	local sig = request.headers["Sign"];

	local curr_nonce = tonumber(request.query["nonce"])
	local prev_nonce = tonumber(storage["nonce:"..key])

	local secret = storage["key:"..key]
	local result = crypto.hmac(secret, query, crypto.sha256).hexdigest()

	if (key ~= nil) and (sig ~= nil) and (curr_nonce ~= nil) and (prev_nonce ~= nil) then
		if (curr_nonce > prev_nonce) and (sig == result) then
			log("Auth: Request successfully verified");
			storage["nonce:"..key] = curr_nonce;
			return true;
		else
			log("Auth: Current nonce is not greater then previous nonce");
		end
	else
		log("Auth: Missing Sig, Key http headers or nonce parameter");
	end

	return false
end

return {
	create_user = create_user,
	delete_user = delete_user,
	authenticate = authenticate,
}
