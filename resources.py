from flask import Blueprint, render_template
from os import listdir, path
from authentication import is_authenticated
from authorization import is_authorized

# Create a Blueprint named 'resources'
resources = Blueprint('resources', __name__)

@resources.route('/<resourceString>', methods=['GET'])
@is_authenticated
@is_authorized()
def get_resource(resourceString):
    """
    Fetch and render a resource template if the user is authenticated and authorized.

    Args:
        resourceString (str): The name of the resource template to fetch.

    Returns:
        str: Rendered HTML template if found.
        tuple: Error message and HTTP status code if the template is not found.
    """
    # List all files in the resourceTemplates directory
    dir_listing = [i.split()[0] for i in listdir('./backend/templates/resourceTemplates')]
    
    # Check if the requested resource template exists
    if resourceString + ".html" not in dir_listing:
        return 'Resource not found', 404
    
    # Render and return the requested resource template
    return render_template('resourceTemplates/' + resourceString + '.html')
