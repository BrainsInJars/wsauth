local create_user = function(username, password)
	storage['user:'..username] = crypto.bcrypt.hash(username..':'..password)
end

local delete_user = function(username)
	storage['user:'..username] = nil
end

local authenticate = function(request)
	return False
end

return {
	create_user = create_user,
	delete_user = delete_user,
	authenticate = authenticate,
}
