from flask import Blueprint, request, make_response, render_template, redirect
from setup import get_mongo_conn
from authentication import is_authenticated
from functools import wraps

# Initialize MongoDB connection
mongo_conn = get_mongo_conn()

# Create a Blueprint for authorization routes
authorization = Blueprint('authorization', __name__)

@authorization.route('/request', methods=['GET', 'POST'])
@is_authenticated
def resource_request():
    """
    Handle resource request by authenticated users.
    GET: Render the request form.
    POST: Process the resource request form submission.
    """
    username = request.username
    collection = mongo_conn['test']['userData']
    roles = collection.find_one({'name': username})['roles']
    managed_roles = get_roles_managed_by_user(username)

    resources = [doc['resource'] for doc in mongo_conn['test']['resourceData'].find()]

    if request.method == 'POST':
        role = request.form['role']

        # Check for resource existence
        if mongo_conn['test']['resourceData'].find_one({'resource': request.form['resource']}) is None:
            return render_template('request.html', error="Resource doesn't exist", roles=roles, resources=resources), 400
        
        # Check for correct roles
        if (role in managed_roles) or ('universal_admin' in roles):
            collection = mongo_conn['test']['resourceData']
            resource_owners = collection.find_one({'resource': request.form['resource']})['resourceOwner']

            if role in set(resource_owners):
                return render_template('request.html', error='Resource already permitted', roles=roles, resources=resources), 400
            
            else:
                collection = mongo_conn['test']['resourceRequest']
                collection.insert_one({ 
                    'resource': request.form['resource'],
                    'requester': username,
                    'role': role
                })

                return redirect('/')
        else:
            return make_response(render_template('request.html', error='Unauthorized or Non Transferable', roles=roles, resources=resources), 403)
    else:
        return render_template('request.html', roles=roles, resources=resources)

@authorization.route('/grant', methods=['GET', 'POST'])
@is_authenticated
def grant():
    """
    Handle granting of resource requests by authenticated users.
    GET: Render the grant form.
    POST: Process the grant form submission.
    """
    username = request.username

    if request.method == 'POST':
        resource = request.form['resource']
        role = request.form['role']
        collection = mongo_conn['test']['resourceRequest']
        collection.delete_one({'resource': resource, 'role': role})

        collection = mongo_conn['test']['resourceData']
        collection.update_one({'resource': resource}, {'$push': {'resourceOwner': role}})

        collection = mongo_conn['test']['roles']
        collection.update_one({'role': role}, {'$push': {'context': resource}})

        return redirect('/')
    else:
        collection = mongo_conn['test']['resourceRequest']
        managed_roles = get_roles_managed_by_user(username, True)
        requests = list(collection.find({'role': {'$in': managed_roles}}))
        if not requests:
            return render_template('grant.html', requests=None)
        return render_template('grant.html', requests=requests)
    
@authorization.route('/registerResource', methods=['GET', 'POST'])
@is_authenticated
def register_resource():
    """
    Handle resource registration by authenticated users.
    GET: Render the resource registration form.
    POST: Process the resource registration form submission.
    """
    username = request.username
    user_roles = get_roles(username)

    if request.method == 'POST':
        print(request.form)
        context_role = request.form['ContextRole']

        if context_role in user_roles:
            collection = mongo_conn['test']['roles']
            curr = collection.find_one({'role': context_role})
            if username in curr['users']['Managers']:
                resource = request.form['resource']
                resource_uri = request.form['resourceURI']
                collection = mongo_conn['test']['resourceData']
                if collection.find_one({'resource': resource}) is None:
                    collection.insert_one({'resource': resource, 'resourceURI': resource_uri, 'resourceOwner': [context_role]})
                    return redirect('/')
                else:
                    return make_response(render_template('registerResource.html', roles= user_roles, error='Resource already exists'), 409)

            return render_template('registerResource.html', roles= user_roles, error='Unauthorized'), 403
        else:
            return render_template('registerResource.html', roles= user_roles, error='Unauthorized'), 403
    else:
        return render_template('registerResource.html', roles= user_roles, error='')

@authorization.route('/createRole', methods=['GET', 'POST'])
@is_authenticated
def create_role():
    """
    Handle role creation by authenticated users.
    GET: Render the role creation form.
    POST: Process the role creation form submission.
    """
    if request.method == 'POST':
        username = request.username
        user_roles = get_roles(username)
        resource_list = set()
        allowed_roles = []

        for role in user_roles:
            collection = mongo_conn['test']['roles']
            curr = collection.find_one({'role': role})
            if username in curr['users']['Managers']:
                allowed_roles.append(role)
                resource_list.update(curr['context'])
        role = request.form['role']
        context = request.form['context'].split(',')
        transferable = bool(request.form.get('transferable', False))
        collection = mongo_conn['test']['roles']

        if not (set(context).issubset(resource_list) or '*' in resource_list):
            return make_response(render_template('newRole.html', error='Invalid Request, Please recheck permissions'), 403)

        if collection.find_one({'role': role}) is None:
            collection.insert_one({
                'role': role,
                'context': context,
                'users': {
                    'Managers': [username],
                    'Users': [username]
                },
                'transferable': transferable
            })
            collection = mongo_conn['test']['userData']
            collection.update_one({'name': username}, {'$push': {'roles': role}})
            collection = mongo_conn['test']['resourceData']
            for resource in context:
                collection.update_one({'resource': resource}, {'$push': {'resourceOwner': role}})
            return redirect('/')
        else:
            return make_response(render_template('newRole.html', error='Role already exists'), 400)
    else:
        return render_template('newRole.html', error='')
    
@authorization.route('/addUserToRole', methods=['GET', 'POST'])
@is_authenticated
def add_user_to_role():
    """
    Handle adding a user to a role by authenticated users.
    GET: Render the add user to role form.
    POST: Process the add user to role form submission.
    """
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        collection = mongo_conn['test']['userData']
        user = collection.find_one({'name': username})

        if user is None:
            return make_response('User does not exist', 400)
        
        if role in get_roles_managed_by_user(request.username, True):
            collection.update_one({'name': username}, {'$push': {'roles': role}})
            return redirect('/')
        
        else:
            return render_template('addUserToRole.html', error='Unauthorized'), 403
    else:
        return render_template('addUserToRole.html')

@authorization.route('/promoteUser', methods=['GET', 'POST'])
@is_authenticated
def promote_user():
    """
    Handle promoting a user to a manager role by authenticated users.
    GET: Render the promote user form.
    POST: Process the promote user form submission.
    """
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        collection = mongo_conn['test']['userData']
        user = collection.find_one({'name': username})

        if user is None:
            return make_response('User does not exist', 400)
        
        if role in get_roles_managed_by_user(request.username, True):
            collection = mongo_conn['test']['roles']
            role_data = collection.find_one({'role': role})
            
            if username in role_data['users']['Managers']:
                return render_template('promoteUser.html', error='User is already a manager'), 400
            
            if username not in role_data['users']['Users']:
                collection.update_one({'name': username}, {'$push': {'roles': role}})
            
            collection.update_one({'role': role}, {'$push': {'users.Managers': username}})
            return redirect('/')
        
        else:
            return render_template('promoteUser.html', error='Unauthorized'), 403
    else:
        return render_template('promoteUser.html')

def get_roles(username):
    """
    Retrieve roles assigned to a user.
    Args:
        username (str): The username of the user.
    Returns:
        list: List of roles assigned to the user.
    """
    collection = mongo_conn['test']['userData']
    user = collection.find_one({'name': username})
    if user is None:
        return []
    return user['roles']

def get_roles_managed_by_user(username, check_for_transferablity=False):
    """
    Retrieve roles managed by a user.
    Args:
        username (str): The username of the user.
        check_for_transferablity (bool): Flag to check for transferable roles.
    Returns:
        list: List of roles managed by the user.
    """
    collection = mongo_conn['test']['roles']
    roles = get_roles(username)

    if 'universal_admin' in roles:
        return [doc['role'] for doc in collection.find()]
    
    managed_roles = []
    
    for role in roles:
        if check_for_transferablity:
            curr = collection.find_one({'role': role, 'transferable': True})
        else: 
            curr = collection.find_one({'role': role})
        if (curr is not None) and (username in curr['users']['Managers']):
            managed_roles.append(role)

    return managed_roles

def get_allowed_resources(username):
    """
    Retrieve resources allowed for a user based on their roles.
    Args:
        username (str): The username of the user.
    Returns:
        list: List of allowed resources.
    """
    roles = get_roles(username)
    resources = set()
    for role in roles:
        collection = mongo_conn['test']['roles']
        curr = collection.find_one({'role': role})
        for resource in curr['context']:
            resources.add(resource)
    
    return list(resources)
                                             
def is_authorized(role=None):
    """
    Decorator to check if a user is authorized to access a resource or perform an action.
    Args:
        role (str): Specific role required for authorization (optional).
    Returns:
        function: Wrapped function with authorization check.
    """
    def decorator(func):
        @wraps(func)
        def authorization_wrapped_function(*args, **kwargs):
            username = request.username
            roles = get_roles(username)

            # Retrieve resourceString from kwargs
            resourceString = request.view_args.get('resourceString', None)

            # Authorization based on resourceString (if applicable)
            if resourceString:
                allowed_resources = get_allowed_resources(username)
                if resourceString in allowed_resources or '*' in allowed_resources:
                    return func(*args, **kwargs)
                else:
                    return make_response('Unauthorized, ResourceNotAllowed', 403)

            # If a specific role is provided, check if the user has that role
            if role and role in roles:
                return func(*args, **kwargs)
            else:
                return make_response('Unauthorized', 403)

        return authorization_wrapped_function
    return decorator
