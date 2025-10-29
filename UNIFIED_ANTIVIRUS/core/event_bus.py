"""
Event Bus - Observer Pattern Implementation  
===========================================

Sistema de comunicación desacoplada entre plugins.
Implementa Publisher-Subscriber (Observer Pattern).
"""

import logging
import threading
import asyncio
from typing import Dict, List, Callable, Any
from collections import defaultdict
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class Event:
    """
    Clase que representa un evento en el sistema.
    Usado por Command Pattern para encapsular información del evento.
    """
    
    def __init__(self, event_type: str, data: Dict[str, Any], source: str = None):
        self.event_type = event_type
        self.data = data
        self.source = source
        self.timestamp = datetime.now()
        self.event_id = f"{event_type}_{self.timestamp.strftime('%Y%m%d_%H%M%S_%f')}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Serializa evento a diccionario"""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type,
            'data': self.data,
            'source': self.source,
            'timestamp': self.timestamp.isoformat()
        }
    
    def __str__(self) -> str:
        return f"Event({self.event_type}, from={self.source}, at={self.timestamp})"


class EventBus:
    """
    Event Bus - Implementación del Observer Pattern.
    
    Permite comunicación desacoplada entre plugins:
    - Detectores publican eventos de amenazas
    - UI se suscribe para actualizar interfaz  
    - Handlers se suscriben para tomar acciones
    
    Thread-safe para uso concurrente.
    """
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.RLock()  # Para thread safety
        self._event_history: List[Event] = []
        self._max_history = 1000  # Mantener últimos 1000 eventos
        
        logger.info("🚌 EventBus inicializado")
    
    def subscribe(self, event_type: str, callback: Callable[[Event], None], 
                 subscriber_name: str = "unknown") -> bool:
        """
        Suscribe un callback a un tipo de evento específico.
        
        Args:
            event_type: Tipo de evento (ej: 'threat_detected', 'scan_complete')
            callback: Función que maneja el evento
            subscriber_name: Nombre del suscriptor para logging
            
        Returns:
            True si la suscripción fue exitosa
        """
        with self._lock:
            try:
                self._subscribers[event_type].append(callback)
                logger.info(f"📋 '{subscriber_name}' suscrito a eventos '{event_type}'")
                return True
            except Exception as e:
                logger.error(f"❌ Error suscribiendo {subscriber_name}: {e}")
                return False
    
    def unsubscribe(self, event_type: str, callback: Callable, 
                   subscriber_name: str = "unknown") -> bool:
        """
        Desuscribe un callback de un tipo de evento.
        """
        with self._lock:
            try:
                if callback in self._subscribers[event_type]:
                    self._subscribers[event_type].remove(callback)
                    logger.info(f"📋❌ '{subscriber_name}' desuscrito de '{event_type}'")
                    return True
                return False
            except Exception as e:
                logger.error(f"❌ Error desuscribiendo {subscriber_name}: {e}")
                return False
    
    def publish(self, event_type: str, data: Dict[str, Any], 
               source: str = "unknown") -> bool:
        """
        Publica un evento a todos los suscriptores.
        
        Args:
            event_type: Tipo de evento a publicar
            data: Datos del evento
            source: Origen del evento (plugin que lo genera)
            
        Returns:
            True si el evento fue publicado exitosamente
        """
        event = Event(event_type, data, source)
        
        with self._lock:
            try:
                # Guardar en historial
                self._event_history.append(event)
                if len(self._event_history) > self._max_history:
                    self._event_history.pop(0)
                
                # Notificar suscriptores
                subscribers = self._subscribers[event_type].copy()
                
                logger.info(f"📢 Publicando evento '{event_type}' de '{source}' "
                           f"a {len(subscribers)} suscriptores")
                
                # Notificar en hilo separado para no bloquear
                threading.Thread(
                    target=self._notify_subscribers,
                    args=(event, subscribers),
                    name=f"EventNotification-{event.event_id}",
                    daemon=True
                ).start()
                
                return True
                
            except Exception as e:
                logger.error(f"❌ Error publicando evento '{event_type}': {e}")
                return False
    
    def _notify_subscribers(self, event: Event, subscribers: List[Callable]):
        """
        Notifica a todos los suscriptores de manera asíncrona.
        Ejecuta en hilo separado para no bloquear el publisher.
        """
        for callback in subscribers:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"❌ Error en callback para evento '{event.event_type}': {e}")
    
    def publish_async(self, event_type: str, data: Dict[str, Any], 
                     source: str = "unknown") -> asyncio.Future:
        """
        Versión asíncrona de publish para plugins que usan async/await.
        """
        loop = asyncio.get_event_loop()
        return loop.run_in_executor(None, self.publish, event_type, data, source)
    
    def get_subscribers_count(self, event_type: str) -> int:
        """Número de suscriptores para un tipo de evento"""
        with self._lock:
            return len(self._subscribers[event_type])
    
    def get_all_event_types(self) -> List[str]:
        """Lista todos los tipos de eventos con suscriptores"""
        with self._lock:
            return list(self._subscribers.keys())
    
    def get_recent_events(self, event_type: str = None, limit: int = 10) -> List[Dict]:
        """
        Obtiene eventos recientes para debugging/monitoring.
        
        Args:
            event_type: Filtrar por tipo de evento (None para todos)
            limit: Número máximo de eventos a retornar
        """
        with self._lock:
            events = self._event_history
            
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            
            # Retornar los más recientes
            recent = events[-limit:] if len(events) > limit else events
            return [event.to_dict() for event in reversed(recent)]
    
    def clear_history(self):
        """Limpia el historial de eventos"""
        with self._lock:
            self._event_history.clear()
            logger.info("🧹 Historial de eventos limpiado")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Estadísticas del event bus para monitoring"""
        with self._lock:
            event_counts = defaultdict(int)
            for event in self._event_history:
                event_counts[event.event_type] += 1
            
            return {
                'total_events': len(self._event_history),
                'event_types': dict(event_counts),
                'subscribers_count': {
                    event_type: len(callbacks) 
                    for event_type, callbacks in self._subscribers.items()
                },
                'active_subscriptions': len(self._subscribers)
            }


# Instancia global del event bus (Singleton pattern implícito)
event_bus = EventBus()


# =================== DECORADOR PARA SUSCRIPCIÓN ===================
def subscribe_to(event_type: str, subscriber_name: str = None):
    """
    Decorador que facilita la suscripción a eventos.
    
    Uso:
    @subscribe_to('threat_detected')
    def handle_threat(event):
        print(f"Amenaza detectada: {event.data}")
    """
    def decorator(func):
        name = subscriber_name or func.__name__
        event_bus.subscribe(event_type, func, name)
        return func
    return decorator