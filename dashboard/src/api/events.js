import axios from 'axios'

const API_BASE_URL = '/api'

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

export const fetchEvents = async (limit = 100) => {
  try {
    const response = await api.get('/events', {
      params: { limit }
    })
    return response.data
  } catch (error) {
    console.error('Error fetching events:', error)
    throw error
  }
}

export const fetchAlerts = async () => {
  try {
    const response = await api.get('/alerts')
    return response.data
  } catch (error) {
    console.error('Error fetching alerts:', error)
    return []
  }
}

export const sendEvent = async (eventData) => {
  try {
    const response = await api.post('/events', eventData)
    return response.data
  } catch (error) {
    console.error('Error sending event:', error)
    throw error
  }
}

export default api