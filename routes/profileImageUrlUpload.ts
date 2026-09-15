/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIp (ip: string): boolean {
  let cleanIp = ip.replace(/^\[|\]$/g, '')
  if (cleanIp.startsWith('::ffff:')) {
    const parts = cleanIp.substring(7)
    if (parts.includes('.')) {
      cleanIp = parts
    } else {
      const hexParts = parts.split(':')
      if (hexParts.length === 2) {
        const p1 = parseInt(hexParts[0], 16)
        const p2 = parseInt(hexParts[1], 16)
        cleanIp = `${(p1 >> 8) & 0xff}.${p1 & 0xff}.${(p2 >> 8) & 0xff}.${p2 & 0xff}`
      }
    }
  }

  const ipv4Match = cleanIp.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (ipv4Match) {
    const p = ipv4Match.slice(1).map(Number)
    if (p.some(octet => octet < 0 || octet > 255)) return true

    const [a, b] = p
    if (a === 0) return true
    if (a === 10) return true
    if (a === 127) return true
    if (a === 100 && b >= 64 && b <= 127) return true
    if (a === 169 && b === 254) return true
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a === 192 && b === 0 && p[2] === 2) return true
    if (a === 198 && b === 51 && p[2] === 100) return true
    if (a === 203 && b === 0 && p[2] === 113) return true
    if (a >= 224) return true

    return false
  }

  const lowerIp = cleanIp.toLowerCase()
  if (
    lowerIp === '::1' ||
    lowerIp === '::' ||
    lowerIp === '0:0:0:0:0:0:0:1' ||
    lowerIp === '0:0:0:0:0:0:0:0' ||
    lowerIp.startsWith('fe80:') ||
    lowerIp.startsWith('fe8') || lowerIp.startsWith('fe9') || lowerIp.startsWith('fea') || lowerIp.startsWith('feb') ||
    lowerIp.startsWith('fc') || lowerIp.startsWith('fd')
  ) {
    return true
  }

  return false
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  try {
    const parsedUrl = new URL(urlString)

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return false
    }

    const hostname = parsedUrl.hostname.toLowerCase()
    if (!hostname || hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal') || hostname.endsWith('.localhost')) {
      return false
    }

    if (isPrivateIp(hostname)) {
      return false
    }

    const addresses = await dns.promises.lookup(hostname, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }

    for (const addr of addresses) {
      if (isPrivateIp(addr.address)) {
        return false
      }
    }

    return true
  } catch {
    return false
  }
}

async function safeFetch (initialUrl: string, maxRedirects = 5): Promise<Response> {
  let currentUrl = initialUrl
  for (let i = 0; i <= maxRedirects; i++) {
    if (!await isSafeUrl(currentUrl)) {
      throw new Error('URL is not allowed due to security restrictions')
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('Redirect status without Location header')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return response
  }
  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await safeFetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
