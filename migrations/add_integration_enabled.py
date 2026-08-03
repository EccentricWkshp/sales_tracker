"""Add enabled flags to integration credentials

Revision ID: add_integration_enabled
Revises: 
Create Date: 2025-01-XX
"""
from alembic import op
import sqlalchemy as sa

def upgrade():
    # Add enabled column (default False for new/existing records)
    op.add_column('ship_station_credentials', 
                  sa.Column('enabled', sa.Boolean(), nullable=False, server_default='0'))
    
    op.add_column('shippo_credentials', 
                  sa.Column('enabled', sa.Boolean(), nullable=False, server_default='0'))
    
    op.add_column('woo_commerce_credentials', 
                  sa.Column('enabled', sa.Boolean(), nullable=False, server_default='0'))

def downgrade():
    op.drop_column('ship_station_credentials', 'enabled')
    op.drop_column('shippo_credentials', 'enabled')
    op.drop_column('woo_commerce_credentials', 'enabled')