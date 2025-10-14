"""
Shippo Orders Retrieval Script
Retrieves orders from Shippo API with pagination and filtering support.
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict
from pathlib import Path

import shippo
from shippo.models import components


@dataclass
class OrderData:
    """Custom class to hold order data"""
    order_id: str
    status: str
    created_at: datetime
    updated_at: datetime
    order_number: Optional[str] = None
    total_price: Optional[str] = None
    currency: Optional[str] = None
    weight: Optional[str] = None
    weight_unit: Optional[str] = None
    to_address: Optional[Dict[str, Any]] = None
    from_address: Optional[Dict[str, Any]] = None
    line_items: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None
    raw_data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for easy serialization"""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        data['created_at'] = self.created_at.isoformat() if self.created_at else None
        data['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        return data


@dataclass
class OrdersResult:
    """Container for orders retrieval results"""
    orders: List[OrderData]
    total_count: int
    retrieved_count: int
    start_date: datetime
    end_date: datetime
    filters_applied: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'orders': [order.to_dict() for order in self.orders],
            'total_count': self.total_count,
            'retrieved_count': self.retrieved_count,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'filters_applied': self.filters_applied
        }


class ShippoOrdersRetriever:
    """Main class for retrieving Shippo orders"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self._setup_logging()
        self._initialize_shippo()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            raise FileNotFoundError(f"Config file not found: {config_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file: {e}")
    
    def _setup_logging(self):
        """Setup logging based on config"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO').upper())
        debug_mode = self.config.get('debug_mode', False)
        
        if debug_mode:
            log_level = logging.DEBUG
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler(self.config.get('log_file', 'shippo_orders.log'))
            ] if self.config.get('log_to_file', True) else [logging.StreamHandler(sys.stdout)]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def _initialize_shippo(self):
        """Initialize Shippo API client"""
        test_mode = self.config.get('test_mode', False)
        
        if test_mode:
            try:
                api_key = self.config.get('shippo_test_api_key')
                if not api_key:
                    raise ValueError("shippo_test_api_key not found in config")
                
                # Initialize modern Shippo SDK
                self.shippo_client = shippo.Shippo(
                    api_key_header=api_key,
                    shippo_api_version=self.config.get('shippo_api_version', '2018-02-08')
                )
                
                self.logger.info("Shippo TEST API client initialized successfully")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize Shippo API: {e}")
                raise
        
        if not test_mode:
            try:
                api_key = self.config.get('shippo_live_api_key')
                if not api_key:
                    raise ValueError("shippo_live_api_key not found in config")
                
                # Initialize modern Shippo SDK
                self.shippo_client = shippo.Shippo(
                    api_key_header=api_key,
                    shippo_api_version=self.config.get('shippo_api_version', '2018-02-08')
                )
                
                self.logger.info("Shippo LIVE API client initialized successfully")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize Shippo API: {e}")
                raise
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime object"""
        try:
            # Try multiple date formats
            formats = [
                '%Y-%m-%d',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%dT%H:%M:%S.%fZ'
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(date_str, fmt)
                    # Ensure timezone awareness
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
            
            raise ValueError(f"Unable to parse date: {date_str}")
            
        except Exception as e:
            self.logger.error(f"Date parsing error: {e}")
            raise
    
    def _convert_order_data(self, order_raw: Dict[str, Any]) -> OrderData:
        """Convert raw Shippo order data to OrderData object"""
        try:
            # Parse dates
            created_at = None
            updated_at = None
            
            # Try different date field names
            for date_field in ['placed_at', 'created', 'created_at']:
                if order_raw.get(date_field):
                    created_at = self._parse_date(order_raw[date_field])
                    break
            
            for date_field in ['updated', 'updated_at', 'modified_at']:
                if order_raw.get(date_field):
                    updated_at = self._parse_date(order_raw[date_field])
                    break

            return OrderData(
                order_id=order_raw.get('object_id', ''),
                status=order_raw.get('order_status', ''),
                created_at=created_at,
                updated_at=updated_at,
                order_number=order_raw.get('order_number'),
                total_price=order_raw.get('total_price'),
                currency=order_raw.get('currency'),
                weight=order_raw.get('weight'),
                weight_unit=order_raw.get('weight_unit'),
                to_address=order_raw.get('to_address'),
                from_address=order_raw.get('from_address'),
                line_items=order_raw.get('line_items', []),
                metadata=order_raw.get('metadata', {}),
                raw_data=order_raw
            )
            
        except Exception as e:
            self.logger.error(f"Error converting order data: {e}")
            raise
    
    def _make_api_request(self, url_path: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make direct API request for orders (fallback if SDK doesn't support orders)"""
        import requests
        
        base_url = self.config.get('shippo_api_url', 'https://api.goshippo.com')
        url = f"{base_url}/{url_path}"
        
        test_mode = self.config.get('test_mode', False)
        
        if test_mode:
            headers = {
                'Authorization': f'ShippoToken {self.config["shippo_test_api_key"]}',
                'Content-Type': 'application/json'
            }
        else:
            headers = {
                'Authorization': f'ShippoToken {self.config["shippo_live_api_key"]}',
                'Content-Type': 'application/json'
            }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            result = response.json()
            
            # Debug logging
            self.logger.debug(f"API URL: {url}")
            self.logger.debug(f"API params: {params}")
            self.logger.debug(f"Response status: {response.status_code}")
            self.logger.debug(f"Response content: {result}")
            
            return result
        
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            raise

    def list_all_orders_debug(self, limit: int = 10) -> Dict[str, Any]:
        """Debug function to list orders without filters"""
        try:
            params = {'page_size': limit}
            response = self._make_api_request('orders', params)
            self.logger.info(f"Debug - All orders response: {json.dumps(response, indent=2, default=str)}")
            return response
        except Exception as e:
            self.logger.error(f"Error in debug function: {e}")
            return {}
    
    def retrieve_orders(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        status_filter: Optional[str] = None,
        order_status: Optional[str] = None
    ) -> OrdersResult:
        """
        Retrieve orders with pagination handling
        
        Args:
            start_date: Start date for filtering (default: 7 days ago)
            end_date: End date for filtering (default: now)
            status_filter: Order status filter (default: 'PAID')
            order_status: Additional order status filter
        """
        
        # Set default dates
        if end_date is None:
            end_date = datetime.now(timezone.utc)
        if start_date is None:
            start_date = end_date - timedelta(days=7)
        
        # Ensure timezone awareness
        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=timezone.utc)
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=timezone.utc)
        
        # Set default status filter
        if order_status is None:
            order_status = 'PAID'  # Completed orders
        
        filters_applied = {
            'order_status': order_status,
            'status_filter': status_filter,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat()
        }
        
        self.logger.info(f"Retrieving orders from {start_date} to {end_date}")
        self.logger.info(f"Applied filters: {filters_applied}")
        
        all_orders = []
        page_size = self.config.get('page_size', 100)
        max_pages = self.config.get('max_pages', 1000)
        
        try:
            # Build query parameters
            params = {
                'page_size': page_size,
                'created_after': start_date.isoformat(),
                'created_before': end_date.isoformat()
            }
            
            # Add order_status with array notation if specified
            if order_status:
                params[f'order_status[]'] = order_status
            
            if status_filter:
                params['status'] = status_filter
            
            page_count = 0
            has_more = True
            next_cursor = None
            
            while has_more and page_count < max_pages:
                self.logger.debug(f"Fetching page {page_count + 1}")
                
                # Add cursor for pagination if available
                if next_cursor:
                    params['page'] = next_cursor
                
                try:
                    # Try to use the SDK first (if orders endpoint is available)
                    try:
                        if hasattr(self.shippo_client, 'orders'):
                            response = self.shippo_client.orders.list(**params)
                            # Convert SDK response to dict format
                            if hasattr(response, '__dict__'):
                                response = response.__dict__
                        else:
                            raise AttributeError("orders not available in SDK")
                    except (AttributeError, Exception) as e:
                        self.logger.info("Using direct API request for orders")
                        # Fallback to direct API request
                        response = self._make_api_request('orders', params)
                    
                    if not response.get('results'):
                        self.logger.info("No more orders found")
                        break
                    
                    # Process orders from this page
                    page_orders = []
                    for order_raw in response['results']:
                        try:
                            order_data = self._convert_order_data(order_raw)
                            
                            # Additional date filtering (API may not be exact)
                            if (order_data.created_at and 
                                start_date <= order_data.created_at <= end_date):
                                page_orders.append(order_data)
                                
                        except Exception as e:
                            self.logger.warning(f"Skipped order due to error: {e}")
                            continue
                    
                    all_orders.extend(page_orders)
                    
                    self.logger.info(f"Page {page_count + 1}: Retrieved {len(page_orders)} orders")
                    
                    # Check for next page
                    has_more = response.get('has_more', False)
                    next_cursor = response.get('next')
                    
                    page_count += 1
                    
                except Exception as e:
                    self.logger.error(f"Error on page {page_count + 1}: {e}")
                    if self.config.get('continue_on_error', True):
                        break
                    else:
                        raise
            
            # Return results
            total_retrieved = len(all_orders)
            
            self.logger.info(f"Total orders retrieved: {total_retrieved}")
            
            return OrdersResult(
                orders=all_orders,
                total_count=total_retrieved,  # Shippo may not provide total count
                retrieved_count=total_retrieved,
                start_date=start_date,
                end_date=end_date,
                filters_applied=filters_applied
            )
                
        except Exception as e:
            self.logger.error(f"Error retrieving orders: {e}")
            if self.config.get('raise_on_error', True):
                raise
            return OrdersResult(
                orders=[],
                total_count=0,
                retrieved_count=0,
                start_date=start_date,
                end_date=end_date,
                filters_applied=filters_applied
            )


def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(description='Retrieve orders from Shippo API')
    
    parser.add_argument('--start-date', type=str, 
                       help='Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--end-date', type=str,
                       help='End date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--order-status', type=str, default='PAID',
                       help='Order status filter (default: PAID)')
    parser.add_argument('--status', type=str,
                       help='Additional status filter')
    parser.add_argument('--config', type=str, default='config.json',
                       help='Config file path (default: config.json)')
    parser.add_argument('--output', type=str,
                       help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    try:
        # Initialize retriever
        retriever = ShippoOrdersRetriever(args.config)
        
        # Parse dates
        start_date = None
        end_date = None
        
        if args.start_date:
            start_date = retriever._parse_date(args.start_date)
        
        if args.end_date:
            end_date = retriever._parse_date(args.end_date)
        
        # Retrieve orders
        result = retriever.retrieve_orders(
            start_date=start_date,
            end_date=end_date,
            order_status=args.order_status,
            status_filter=args.status
        )
        
        # Output results
        print(f"Retrieved {result.retrieved_count} orders")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            print(f"Results saved to {args.output}")
        
        return result
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()