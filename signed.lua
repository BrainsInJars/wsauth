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

	log(query, key, sig)

	if key == nil or sig == nil then
		return False;
	end

	local curr_nonce = tonumber(request.query["nonce"])
	local prev_nonce = tonumber(storage["nonce:"..key])

	log(curr_nonce, prev_nonce);

	if curr_nonce == nil or prev_nonce == nil then
		return False;
	end

	if not (curr_nonce > prev_nonce) then
		return False;
	end

	local secret = storage["key:"..key]
	local result = crypto.hmac(secret, query, crypto.sha256).hexdigest()

	log(result)

	if sig ~= result then
		return False;
	end
	storage["nonce:"..key] = curr_nonce

	return True;
end

return {
	create_user = create_user,
	delete_user = delete_user,
	authenticate = authenticate,
}
