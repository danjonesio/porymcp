'use client'

import { Logo } from '@/app/logo'
import {
  Dropdown,
  DropdownButton,
  DropdownDivider,
  DropdownItem,
  DropdownLabel,
  DropdownMenu,
} from '@/components/dropdown'
import { Navbar, NavbarItem, NavbarSection, NavbarSpacer } from '@/components/navbar'
import {
  Sidebar,
  SidebarBody,
  SidebarFooter,
  SidebarHeader,
  SidebarItem,
  SidebarLabel,
  SidebarSection,
} from '@/components/sidebar'
import { SidebarLayout } from '@/components/sidebar-layout'
import { clearAdminKey } from '@/lib/api'
import {
  ArrowRightStartOnRectangleIcon,
  CircleStackIcon,
  Cog8ToothIcon,
  HomeIcon,
  KeyIcon,
  QueueListIcon,
  RectangleGroupIcon,
} from '@heroicons/react/16/solid'
import { usePathname, useRouter } from 'next/navigation'

export function ApplicationLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const router = useRouter()

  function signOut() {
    clearAdminKey()
    router.push('/login/')
  }

  return (
    <SidebarLayout
      navbar={
        <Navbar>
          <NavbarSpacer />
          <NavbarSection>
            <NavbarItem href="/settings/" aria-label="Settings">
              <Cog8ToothIcon />
            </NavbarItem>
          </NavbarSection>
        </Navbar>
      }
      sidebar={
        <Sidebar>
          <SidebarHeader>
            <SidebarItem href="/" aria-label="Homepage">
              <Logo />
            </SidebarItem>
          </SidebarHeader>
          <SidebarBody>
            <SidebarSection>
              <SidebarItem href="/" current={pathname === '/'}>
                <HomeIcon />
                <SidebarLabel>Overview</SidebarLabel>
              </SidebarItem>
              <SidebarItem href="/upstreams/" current={pathname.startsWith('/upstreams')}>
                <CircleStackIcon />
                <SidebarLabel>Upstreams</SidebarLabel>
              </SidebarItem>
              <SidebarItem href="/groups/" current={pathname.startsWith('/groups')}>
                <RectangleGroupIcon />
                <SidebarLabel>Groups</SidebarLabel>
              </SidebarItem>
              <SidebarItem href="/virtual-keys/" current={pathname.startsWith('/virtual-keys')}>
                <KeyIcon />
                <SidebarLabel>Virtual keys</SidebarLabel>
              </SidebarItem>
              <SidebarItem href="/logs/" current={pathname.startsWith('/logs')}>
                <QueueListIcon />
                <SidebarLabel>Logs</SidebarLabel>
              </SidebarItem>
              <SidebarItem href="/settings/" current={pathname.startsWith('/settings')}>
                <Cog8ToothIcon />
                <SidebarLabel>Settings</SidebarLabel>
              </SidebarItem>
            </SidebarSection>
          </SidebarBody>
          <SidebarFooter className="max-lg:hidden">
            <Dropdown>
              <DropdownButton as={SidebarItem}>
                <span className="grid min-w-0 grid-cols-[auto_1fr] items-center gap-3">
                  {/* A static monogram, hidden from assistive tech: the two
                      lines beside it are the trigger's accessible name. */}
                  <span
                    aria-hidden="true"
                    className="grid size-8 shrink-0 place-items-center rounded-[20%] bg-cyan-600 text-sm font-semibold text-white select-none"
                  >
                    PM
                  </span>
                  <span className="min-w-0 text-zinc-950 dark:text-white">
                    <span className="block truncate text-sm/5 font-medium">Admin</span>
                    <span className="block truncate text-xs/5 text-zinc-500 dark:text-zinc-400">Management API</span>
                  </span>
                </span>
              </DropdownButton>
              <DropdownMenu className="min-w-64" anchor="top start">
                <DropdownItem href="/settings/">
                  <Cog8ToothIcon />
                  <DropdownLabel>Settings</DropdownLabel>
                </DropdownItem>
                <DropdownDivider />
                <DropdownItem onClick={signOut}>
                  <ArrowRightStartOnRectangleIcon />
                  <DropdownLabel>Sign out</DropdownLabel>
                </DropdownItem>
              </DropdownMenu>
            </Dropdown>
          </SidebarFooter>
        </Sidebar>
      }
    >
      {children}
    </SidebarLayout>
  )
}
